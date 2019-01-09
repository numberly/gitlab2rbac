#!/usr/bin/python env

import logging
from os import environ
from time import sleep

import kubernetes
from gitlab import Gitlab
from kubernetes.client.rest import ApiException
from slugify import slugify

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO
)


class GitlabHelper(object):

    ACCESS_LEVEL_REFERENCE = {
        10: "guest",
        20: "reporter",
        30: "developer",
        40: "maintainer",
        50: "owner",
    }

    def __init__(self, url, token, timeout, groups, namespace_granularity):
        self.client = None
        self.gitlab_users = []
        self.groups = groups
        self.timeout = timeout
        self.token = token
        self.url = url

        self.namespaces = self.get_projects
        if namespace_granularity == "group":
            self.namespaces = self.get_groups

    def connect(self):
        """Performs an authentication via private token.

        Raises:
            exception: If any errors occurs.
        """
        try:
            self.client = Gitlab(
                url=self.url, private_token=self.token, timeout=self.timeout
            )
            self.client.auth()
        except Exception as e:
            raise Exception("unable to connect on gitlab :: {}".format(e))

    def get_projects(self):
        """Get all projects under the configured namespace (GITLAB_GROUP_SEARCH).

        Returns:
            list[gitlab.Project]: list for success, empty otherwise.
        """
        try:
            projects = []
            for group in self.get_groups():
                for project in group.projects.list(all=True):
                    projects.append(self.client.projects.get(project.id))
                    logging.info(
                        "|_ search group={} project={}".format(
                            group.name, project.name
                        )
                    )
            return projects
        except Exception as e:
            logging.error("unable to get groups :: {}".format(e))
        return []

    def get_users(self):
        """Returns all users from groups/projects.

        e.g. user {
                'access_level': 'reporter',
                'email': 'foo@bar.com',
                'id': '123',
                'namespace': 'default'
            }

        Returns:
            list[dict]: list for success, empty otherwise.
        """
        try:
            users = []
            for namespace in self.namespaces():
                for member in namespace.members.list():
                    user = self.client.users.get(member.id)
                    users.append(
                        {
                            "access_level": member.access_level,
                            "email": user.email,
                            "id": "{}".format(user.id),
                            "namespace": slugify(namespace.name),
                        }
                    )
                    logging.info(
                        u"|__ found user={} email={} access_level={}".format(
                            user.name, user.email, member.access_level
                        )
                    )
            return users
        except Exception as e:
            logging.error("unable to retrieve users :: {}".format(e))
        return []

    def get_groups(self):
        groups = []
        for group in self.groups:
            for result in self.client.groups.list(search=group, all=True):
                logging.info(u"|found group={}".format(result.name))
                groups.append(result)
        return groups


class KubernetesHelper(object):

    PROTECTED_NAMESPACES = ["kube-system"]

    def __init__(
        self, timeout, load_incluster_config, user_role_prefix="gitlab2rbac"
    ):
        self.client_rbac = None
        self.client_core = None
        self.timeout = timeout
        self.load_incluster_config = load_incluster_config
        self.user_role_prefix = user_role_prefix

    def connect(self):
        try:
            if self.load_incluster_config:
                # it works only if this script is run by K8s as a POD
                kubernetes.config.load_incluster_config()
            else:
                kubernetes.config.load_kube_config()
            self.client_rbac = kubernetes.client.RbacAuthorizationV1Api()
            self.client_core = kubernetes.client.CoreV1Api()
        except Exception as e:
            logging.error("unable to connect :: {}".format(e))
            raise

    def get_namespaces(self):
        try:
            return [
                namespace.metadata.name
                for namespace in self.client_core.list_namespace(
                    _request_timeout=self.timeout
                ).items
                if namespace.metadata.name not in self.PROTECTED_NAMESPACES
            ]
        except ApiException as e:
            error = "unable to retrieve namespaces :: {}".format(
                eval(e.body)["message"]
            )
            logging.error(error)
        except Exception as e:
            logging.error("unable to retrieve namespaces :: {}".format(e))
        return []

    def auto_create(self, namespaces):
        try:
            for namespace in namespaces:
                slug_namespace = slugify(namespace.name)
                labels = {
                    "app.kubernetes.io/name": slug_namespace,
                    "app.kubernetes.io/managed-by": "gitlab2rbac"
                }
                if self.check_namespace(name=slug_namespace):
                    continue
                metadata = kubernetes.client.V1ObjectMeta(
                    name=slug_namespace, labels=labels)
                namespace_body = kubernetes.client.V1Namespace(
                    metadata=metadata
                )
                self.client_core.create_namespace(body=namespace_body)
                logging.info("auto create namespace={}".format(slug_namespace))
        except ApiException as e:
            error = "unable to auto create :: {}".format(
                eval(e.body)["message"]
            )
            logging.error(error)
        except Exception as e:
            logging.error("unable to auto create:: {}".format(e))
        return []

    def check_namespace(self, name):
        """Check if namespace exists.

           Args:
               name (str): kubernetes namespace.

           Returns:
               bool: True if exists, False otherwise.
        """
        try:
            namespace = self.client_core.list_namespace(
                field_selector="metadata.name={}".format(name),
                timeout_seconds=self.timeout,
            )
            return bool(namespace.items)
        except ApiException as e:
            error = "unable to check namespace :: {}".format(
                eval(e.body)["message"]
            )
            logging.error(error)
        except Exception as e:
            logging.error("unable to check namespace :: {}".format(e))
        return False

    def check_user_role_binding(self, namespace, name):
        """Check if user_role_binding exists.

           Args:
               namespace (str): kubernetes namespace.
               name (str): user_role_binding name.

           Returns:
               bool: True if exists, False otherwise.
        """
        try:
            role_bindings = self.client_rbac.list_namespaced_role_binding(
                namespace=namespace,
                field_selector="metadata.name={}_{}".format(
                    self.user_role_prefix, name
                ),
                timeout_seconds=self.timeout,
            )
            return bool(role_bindings.items)
        except ApiException as e:
            error = "unable to check user role binding :: {}".format(
                eval(e.body)["message"]
            )
            logging.error(error)
        except Exception as e:
            logging.error("unable to check user role binding :: {}".format(e))
        return False

    def create_user_role_binding(
        self, user, user_id, name, namespace, role_ref
    ):
        try:
            labels = {
                "app.kubernetes.io/managed-by": "gitlab2rbac",
                "gitlab2rbac.kubernetes.io/role_ref": role_ref,
                "gitlab2rbac.kubernetes.io/user_id": user_id,
            }
            name = "{}_{}".format(self.user_role_prefix, name)
            role_binding = kubernetes.client.V1RoleBinding(
                metadata=kubernetes.client.V1ObjectMeta(
                    namespace=namespace, name=name, labels=labels
                ),
                subjects=[
                    kubernetes.client.V1Subject(
                        name=user,
                        kind="User",
                        api_group="rbac.authorization.k8s.io",
                    )
                ],
                role_ref=kubernetes.client.V1RoleRef(
                    kind="ClusterRole",
                    api_group="rbac.authorization.k8s.io",
                    name="gitlab2rbac:{}".format(role_ref),
                ),
            )
            self.client_rbac.create_namespaced_role_binding(
                namespace=namespace,
                body=role_binding,
                _request_timeout=self.timeout,
            )
            logging.info(
                u"|_ role-binding created name={} namespace={}".format(
                    name, namespace
                )
            )
        except ApiException as e:
            error = "unable to create user role binding :: {}".format(
                eval(e.body)["message"]
            )
            logging.error(error)
        except Exception as e:
            logging.error("unable to create user role binding :: {}".format(e))

    def delete_deprecated_user_role_bindings(self, users):
        try:
            users_ids = [user["id"] for user in users]
            role_bindings = (
                self.client_rbac.list_role_binding_for_all_namespaces()
            )

            for role_binding in role_bindings.items:
                if not role_binding.metadata.labels:
                    continue

                if "gitlab2rbac.kubernetes.io/user_id" not in role_binding.metadata.labels:
                    continue

                if role_binding.metadata.labels["gitlab2rbac.kubernetes.io/user_id"] in users_ids:
                    continue

                self.client_rbac.delete_namespaced_role_binding(
                    name=role_binding.metadata.name,
                    namespace=role_binding.metadata.namespace,
                    body=role_binding,
                )
                logging.info(
                    u"|_ role-binding deprecated name={} namespace={}".format(
                        role_binding.metadata.name,
                        role_binding.metadata.namespace,
                    )
                )
        except ApiException as e:
            error = "unable to delete deprecated user role bindings :: {}".format(
                eval(e.body)["message"]
            )
            logging.error(error)
        except Exception as e:
            logging.error(
                "unable to delete deprecated user role bindings :: {}".format(
                    e
                )
            )


class Gitlab2RBAC(object):
    def __init__(
            self, gitlab, kubernetes, kubernetes_auto_create):
        self.gitlab = gitlab
        self.kubernetes = kubernetes
        self.kubernetes_auto_create = kubernetes_auto_create
        self.gitlab_users = self.gitlab.get_users()

    def __call__(self):
        if self.kubernetes_auto_create:
            self.kubernetes.auto_create(namespaces=self.gitlab.namespaces())

        self.create_user_role_bindings()

    def create_user_role_bindings(self):
        try:
            for user in self.gitlab_users:
                namespace = user["namespace"]
                access_level = self.gitlab.ACCESS_LEVEL_REFERENCE[
                    user["access_level"]
                ]
                role_binding_name = "{}_{}".format(user["email"], access_level)

                if not self.kubernetes.check_user_role_binding(
                    namespace=namespace, name=role_binding_name
                ):
                    self.kubernetes.create_user_role_binding(
                        user=user["email"],
                        user_id=user["id"],
                        name=role_binding_name,
                        namespace=namespace,
                        role_ref=access_level,
                    )

            self.kubernetes.delete_deprecated_user_role_bindings(
                users=self.gitlab_users
            )
        except Exception as e:
            logging.error(
                "unable to create user role bindings :: {}".format(e)
            )


def main():
    try:
        GITLAB_URL = environ.get("GITLAB_URL", None)
        GITLAB_PRIVATE_TOKEN = environ.get("GITLAB_PRIVATE_TOKEN", None)
        GITLAB_TIMEOUT = environ.get("GITLAB_TIMEOUT", 10)
        GITLAB_GROUPS_SEARCH = environ.get("GITLAB_GROUPS_SEARCH", "gitlab2rbac").split(",")
        GITLAB_NAMESPACE_GRANULARITY = environ.get("GITLAB_NAMESPACE_GRANULARITY", "project")

        KUBERNETES_TIMEOUT = environ.get("KUBERNETES_TIMEOUT", 10)
        KUBERNETES_AUTO_CREATE = eval(
            environ.get("KUBERNETES_AUTO_CREATE", "False")
        )
        KUBERNETES_LOAD_INCLUSTER_CONFIG = eval(
            environ.get("KUBERNETES_LOAD_INCLUSTER_CONFIG", "False")
        )

        GITLAB2RBAC_FREQUENCY = environ.get("GITLAB2RBAC_FREQUENCY", 60)

        if not GITLAB_URL or not GITLAB_PRIVATE_TOKEN:
            raise Exception(
                "missing variables GITLAB_URL / GITLAB_PRIVATE_TOKEN"
            )

        while True:
            gitlab_helper = GitlabHelper(
                url=GITLAB_URL,
                token=GITLAB_PRIVATE_TOKEN,
                timeout=GITLAB_TIMEOUT,
                groups=GITLAB_GROUPS_SEARCH,
                namespace_granularity=GITLAB_NAMESPACE_GRANULARITY
            )
            gitlab_helper.connect()

            kubernertes_helper = KubernetesHelper(
                timeout=KUBERNETES_TIMEOUT,
                load_incluster_config=KUBERNETES_LOAD_INCLUSTER_CONFIG,
            )
            kubernertes_helper.connect()

            rbac = Gitlab2RBAC(
                gitlab=gitlab_helper,
                kubernetes=kubernertes_helper,
                kubernetes_auto_create=KUBERNETES_AUTO_CREATE,
            )
            rbac()
            sleep(int(GITLAB2RBAC_FREQUENCY))
    except Exception as e:
        logging.error("{}".format(e))
        exit(1)


if __name__ == "__main__":
    main()
