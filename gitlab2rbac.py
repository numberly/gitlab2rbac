import json
import logging
from collections import defaultdict
from contextlib import suppress
from os import environ
from time import sleep, time
from typing import Any

import kubernetes
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport
from gitlab import Gitlab
from gitlab.v4.objects import Project, Group
from kubernetes.client.rest import ApiException
from slugify import slugify

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=environ.get("LOGLEVEL", "INFO").upper(),
)

logging.getLogger("gql").setLevel(logging.WARNING)


class GitlabHelper:
    ACCESS_LEVEL_REFERENCE: dict[int, str] = {
        10: "guest",
        20: "reporter",
        30: "developer",
        40: "maintainer",
        # NOTE: owner is only usable when your permissions are based on group.
        50: "maintainer",
    }

    def __init__(
        self,
        url: str,
        token: str,
        timeout: int,
        groups: list[str],
        namespace_granularity: str,
        admins_group: str | None,
        username_ignore_list: list[str],
        groups_ignore_list: list[str],
        namespace_mapping: dict[str, list[str]] | None = None,
    ) -> None:
        self.client: Gitlab | None = None
        self.gitlab_users: list[dict[str, Any]] = []
        self.groups = groups
        self.timeout = timeout
        self.token = token
        self.url = url
        self.namespace_granularity = namespace_granularity
        self.admins_group = admins_group
        self.namespaces: list[tuple[Group | Project, str]] = []
        self.username_ignore_list = username_ignore_list
        self.groups_ignore_list = groups_ignore_list
        self.namespace_mapping = namespace_mapping or {}
        self.namespace_name_mapping: dict[str, list[str]] = {}

    def connect(self) -> None:
        """Performs an authentication via private token.

        Raises:
            Exception: If any errors occurs.
        """
        try:
            self.client = Gitlab(
                url=self.url, private_token=self.token, timeout=self.timeout
            )
            self.client.auth()
        except Exception as e:
            raise Exception("unable to connect on gitlab :: {}".format(e))

        try:
            mapped_gitlab_ids = set()
            for gitlab_path, k8s_namespaces in self.namespace_mapping.items():
                namespace_obj = self.get_specific_group(gitlab_path)
                if namespace_obj:
                    mapped_gitlab_ids.add(namespace_obj.id)
                    for k8s_namespace in k8s_namespaces:
                        self.namespaces.append((namespace_obj, k8s_namespace))
                    
                    self.namespace_name_mapping[namespace_obj.name] = k8s_namespaces
                    self.namespace_name_mapping[gitlab_path] = k8s_namespaces
            
            if self.namespace_granularity == "group":
                regular_namespaces = self.get_groups()
            else:
                regular_namespaces = self.get_projects()
            
            for ns in regular_namespaces:
                if ns.id not in mapped_gitlab_ids:
                    k8s_name = slugify(ns.name)
                    self.namespaces.append((ns, k8s_name))
                    self.namespace_name_mapping[ns.name] = [k8s_name]
                    
        except Exception as e:
            raise Exception("unable to define namespaces :: {}".format(e))

    def get_projects(self) -> list[Project]:
        """Get all projects under the configured namespace (GITLAB_GROUP_SEARCH).

        Returns:
            list[Project]: list for success, empty otherwise.
        """

        try:
            projects: list[Project] = []
            if self.client is None:
                logging.error("Gitlab client is not connected.")
                return projects
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
            logging.error("unable to get projects :: {}".format(e))
        return []

    def get_admins(self) -> list[dict[str, str]]:
        """Returns all admins.

        e.g. user {
                'email': 'foo@bar.com',
                'id': '123',
            }

        Returns:
            list[dict[str, str]]: list for success, empty otherwise.
        """
        try:
            if self.admins_group:
                if self.client is None:
                    logging.error("Gitlab client is not connected.")
                    return []
                ns_list = self.client.groups.list(search=self.admins_group)
                ns_tuples = [(ns, "admin") for ns in ns_list]
                return self.get_users(from_namespaces=ns_tuples) or []

            admins: list[dict[str, str]] = []
            if self.client is None:
                logging.error("Gitlab client is not connected.")
                return admins
            for user in self.client.users.list(all=True):
                if user.is_admin:
                    admins.append(
                        {"email": user.email, "id": "{}".format(user.id)}
                    )
                    logging.info(
                        "|user={} email={} access_level=admin".format(
                            user.name, user.email
                        )
                    )
            return admins
        except Exception as e:
            logging.error("unable to retrieve admins :: {}".format(e))
            exit(1)
        return []

    def check_user(self, user: dict[str, Any]) -> bool:
        if user["bot"] is True:
            logging.debug(f"Ignore user {user['username']} because it's a bot")
            return False
        if user["username"] in self.username_ignore_list:
            logging.debug(
                f"Ignore user {user['username']} because it's in the ignore list"
            )
            return False
        if user["state"] != "active":
            logging.debug(
                f"Ignoring user {user['username']} because is not active"
            )
            return False
        return True

    def _get_users_query_paginated(
        self,
        gql_client: Client,
        query: Any,
        variable_values: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        if variable_values is None:
            variable_values = {}
        variable_values["first"] = 50
        gql_client.execute(
            query, variable_values=variable_values, parse_result=True
        )
        nodes: list[dict[str, Any]] = []
        page_info: dict[str, Any] = {"hasNextPage": True}
        while page_info.get("hasNextPage"):
            variable_values["after"] = page_info.get("endCursor")
            results = (
                gql_client.execute(
                    query, variable_values=variable_values, parse_result=True
                )
                .get("group")
                .get("groupMembers")
            )
            nodes += results.get("nodes")
            page_info = results.get("pageInfo")
        return nodes

    def get_users(
        self, from_namespaces: list[tuple[Group | Project, str]] | None = None
    ) -> list[dict[str, Any]]:
        """Returns all users from groups/projects.
        We use a GraphQL to minimize the queries made to Gitlab API

        Args:
          from_namespaces: Retrieve users from this namespaces.
              Namespaces should be given as a list of 2-tuples with the
              namespace object and the corresponding k8s namespace
              e.g. [(group_obj, "spark-operator"), (project_obj, "data-platform")]

        Returns:
            list[dict[str, Any]]: list for success, empty otherwise.
            e.g. user {
                'access_level': 'reporter',
                'email': 'foo@bar.com',
                'id': '123',
                'namespace': 'default'
            }
        """
        try:
            users: list[dict[str, Any]] = []
            namespace_tuples = from_namespaces or self.namespaces
            query = gql(
                """
query ($first: Int, $after: String, $namespace : ID!) {
  group(fullPath: $namespace) {
    id
    name
    parent {
      id
    }
    groupMembers(first: $first, after: $after) {
      pageInfo {
        endCursor
        hasNextPage
      }
      nodes {
        id
        accessLevel {
          integerValue
          stringValue
        }
        user {
          id
          bot
          username
          state
          emails {
            edges {
              node {
               email
              }
            }
          }
        }
      }
    }
  }
}
"""
            )
            transport = RequestsHTTPTransport(
                url=f"{self.url}/api/graphql",
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                },
                use_json=True,
            )
            client = Client(
                transport=transport, fetch_schema_from_transport=True
            )
            
            for namespace_obj, k8s_namespace in namespace_tuples:
                _start = time()
                variable_values = {"namespace": namespace_obj.name}
                members = self._get_users_query_paginated(
                    client, query, variable_values
                )
                timespent = time() - _start
                logging.debug(
                    f"Fetched members of group {namespace_obj.name} for k8s namespace {k8s_namespace} in {timespent} seconds"
                )
                for member in members:
                    # ignore user if it doesn't pass some checks
                    if not self.check_user(member["user"]):
                        continue
                    
                    user = {
                        "access_level": member["accessLevel"]["integerValue"],
                        "email": member["user"]["emails"]["edges"][0]["node"][
                            "email"
                        ],
                        "id": member["user"]["id"].replace(
                            "gid://gitlab/User/", ""
                        ),
                        "namespace": k8s_namespace,
                        "username": member["user"]["username"],
                    }
                    users.append(user)
                    logging.info(
                        "|gitlab={} k8s_namespace={} user={} email={} access_level={}".format(
                            namespace_obj.name,
                            k8s_namespace,
                            user["username"],
                            user["email"],
                            user["access_level"],
                        )
                    )
            return users
        except Exception as e:
            logging.error("unable to retrieve users :: {}".format(e))
            exit(1)
        return []

    def get_specific_group(self, full_path: str) -> Group | Project | None:
        """Get a specific group or project by its full path.

        Args:
            full_path: Full path to the group or project (e.g., "project/kubernetes/spark")

        Returns:
            Group or Project object if found, None otherwise.
        """
        if self.client is None:
            logging.error("Gitlab client is not connected.")
            return None

        # Try to get `full_path` as either a group or a project
        with suppress(Exception):
            group = self.client.groups.get(full_path)
            logging.info(f"|found mapped group={full_path}")
            return group

        with suppress(Exception):
            project = self.client.projects.get(full_path)
            logging.info(f"|found mapped project={full_path}")
            return project

        logging.warning(f"Unable to find group or project at path: {full_path}")
        return None

    def get_groups(self) -> list[Group]:
        groups: list[Group] = []
        if self.client is None:
            logging.error("Gitlab client is not connected.")
            return groups
        for group in self.groups:
            _start = time()
            gitlab_groups = self.client.groups.list(
                search=group,
                top_level_only=True,
                all=True,
            )
            timespent = time() - _start
            logging.debug(f"Fetched groups in {timespent} seconds")
            for result in gitlab_groups:
                if result.name not in self.groups_ignore_list:
                    logging.info("|found group={}".format(result.name))
                    groups.append(result)
        return groups


class KubernetesHelper:
    PROTECTED_NAMESPACES: list[str] = ["kube-system"]

    def __init__(
        self,
        timeout: int,
        load_incluster_config: bool,
        user_role_prefix: str = "gitlab2rbac",
    ) -> None:
        self.client_rbac: kubernetes.client.RbacAuthorizationV1Api | None = (
            None
        )
        self.client_core: kubernetes.client.CoreV1Api | None = None
        self.timeout = timeout
        self.load_incluster_config = load_incluster_config
        self.user_role_prefix = user_role_prefix

    def connect(self) -> None:
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

    def get_namespaces(self) -> list[str]:
        try:
            if self.client_core is None:
                logging.error("Kubernetes CoreV1Api client is not connected.")
                return []
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

    def auto_create(self, namespaces: list[tuple[Group | Project, str]]) -> list[Any]:
        try:
            if self.client_core is None:
                logging.error("Kubernetes CoreV1Api client is not connected.")
                return []
            
            for namespace_obj, k8s_namespace in namespaces:
                labels = {
                    "app.kubernetes.io/name": k8s_namespace,
                    "app.kubernetes.io/managed-by": "gitlab2rbac",
                    "gitlab2rbac.kubernetes.io/gitlab-name": namespace_obj.name,
                }
                if self.check_namespace(name=k8s_namespace):
                    continue
                metadata = kubernetes.client.V1ObjectMeta(
                    name=k8s_namespace, labels=labels
                )
                namespace_body = kubernetes.client.V1Namespace(
                    metadata=metadata
                )
                self.client_core.create_namespace(body=namespace_body)
                logging.info("auto create namespace={} (gitlab={})".format(k8s_namespace, namespace_obj.name))
        except ApiException as e:
            error = "unable to auto create :: {}".format(
                eval(e.body)["message"]
            )
            logging.error(error)
        except Exception as e:
            logging.error("unable to auto create:: {}".format(e))
        return []

    def check_namespace(self, name: str) -> bool:
        """Check if namespace exists.

        Args:
            name: kubernetes namespace.

        Returns:
            True if exists, False otherwise.
        """
        try:
            if self.client_core is None:
                logging.error("Kubernetes CoreV1Api client is not connected.")
                return False
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

    def check_role_binding(
        self, name: str, namespace: str | None = None
    ) -> bool:
        """Check if role binding exists.

        Args:
            name: user_role_binding name.
            namespace: kubernetes namespace.

        Returns:
            True if exists, False otherwise.
        """
        try:
            if self.client_rbac is None:
                logging.error("Rbac client is not connected.")
                return False
            full_name = "{}_{}".format(self.user_role_prefix, name)
            field_selector = "metadata.name={}".format(full_name)
            if namespace:
                role_bindings = self.client_rbac.list_namespaced_role_binding(
                    namespace=namespace,
                    field_selector=field_selector,
                    timeout_seconds=self.timeout,
                )
            else:
                role_bindings = self.client_rbac.list_cluster_role_binding(
                    field_selector=field_selector, timeout_seconds=self.timeout
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

    def create_role_binding(
        self,
        user: str,
        user_id: str,
        name: str,
        role_ref: str,
        namespace: str | None = None,
    ) -> None:
        try:
            if self.client_rbac is None:
                logging.error("Rbac client is not connected.")
                return
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
                    kubernetes.client.RbacV1Subject(
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
            if namespace:
                self.client_rbac.create_namespaced_role_binding(
                    namespace=namespace,
                    body=role_binding,
                    _request_timeout=self.timeout,
                )
            else:
                self.client_rbac.create_cluster_role_binding(
                    body=role_binding, _request_timeout=self.timeout
                )
            logging.info(
                "|_ role-binding created name={} namespace={}".format(
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

    def delete_deprecated_user_role_bindings(
        self, users: list[dict[str, Any]]
    ) -> None:
        try:
            if self.client_rbac is None:
                logging.error("Rbac client is not connected.")
                return
            users_grouped_by_ns = defaultdict(list)
            for user in users:
                users_grouped_by_ns[user["namespace"]].append(user)

            for ns in users_grouped_by_ns:
                role_bindings = self.client_rbac.list_namespaced_role_binding(
                    ns
                )
                users_ids = [user["id"] for user in users_grouped_by_ns[ns]]

                for role_binding in role_bindings.items:
                    try:
                        user_id = role_binding.metadata.labels[
                            "gitlab2rbac.kubernetes.io/user_id"
                        ]
                    except (TypeError, KeyError):
                        continue

                    if user_id not in users_ids:
                        self.client_rbac.delete_namespaced_role_binding(
                            name=role_binding.metadata.name,
                            namespace=role_binding.metadata.namespace,
                            body=role_binding,
                        )
                        logging.info(
                            "|_ role-binding deprecated name={} namespace={}".format(
                                role_binding.metadata.name,
                                role_binding.metadata.namespace,
                            )
                        )
        except ApiException as e:
            error = (
                "unable to delete deprecated user role bindings :: {}".format(
                    eval(e.body)["message"]
                )
            )
            logging.error(error)
        except Exception as e:
            logging.error(
                "unable to delete deprecated user role bindings :: {}".format(
                    e
                )
            )

    def delete_deprecated_cluster_role_bindings(
        self, users: list[dict[str, Any]]
    ) -> None:
        try:
            if self.client_rbac is None:
                logging.error("Rbac client is not connected.")
                return
            cluster_users_ids = [user["id"] for user in users]
            for (
                role_binding
            ) in self.client_rbac.list_cluster_role_binding().items:
                try:
                    user_id = role_binding.metadata.labels[
                        "gitlab2rbac.kubernetes.io/user_id"
                    ]
                except (TypeError, ValueError, KeyError):
                    continue

                if user_id not in cluster_users_ids:
                    self.client_rbac.delete_cluster_role_binding(
                        name=role_binding.metadata.name,
                        body=role_binding,
                    )
                    logging.info(
                        "|_ cluster-role-binding deprecated name={}".format(
                            role_binding.metadata.name,
                        )
                    )
        except ApiException as e:
            error = "unable to delete deprecated cluster role bindings :: {}".format(
                eval(e.body)["message"]
            )
            logging.error(error)
        except Exception as e:
            logging.error(
                "unable to delete deprecated cluster role bindings :: {}".format(
                    e
                )
            )


class Gitlab2RBAC:
    def __init__(
        self,
        gitlab: GitlabHelper,
        kubernetes: KubernetesHelper,
        kubernetes_auto_create: bool,
    ) -> None:
        self.gitlab = gitlab
        self.kubernetes = kubernetes
        self.kubernetes_auto_create = kubernetes_auto_create

    def __call__(self) -> None:
        if self.kubernetes_auto_create:
            # When auto-creating, create namespaces first, then fetch all users
            self.kubernetes.auto_create(namespaces=self.gitlab.namespaces)
            gitlab_users = self.gitlab.get_users()
        else:
            # When not auto-creating, filter namespaces first, then fetch users only from existing ones
            existing_k8s_namespaces = set(self.kubernetes.get_namespaces())
            
            filtered_namespaces = []
            missing_namespaces = set()
            skipped_gitlab_groups = set()
            
            for gitlab_obj, k8s_namespace in self.gitlab.namespaces:
                if k8s_namespace in existing_k8s_namespaces:
                    filtered_namespaces.append((gitlab_obj, k8s_namespace))
                else:
                    missing_namespaces.add(k8s_namespace)
                    skipped_gitlab_groups.add(gitlab_obj.name)
            
            if missing_namespaces:
                logging.warning(
                    f"Found {len(missing_namespaces)} non-existent Kubernetes namespace(s). "
                    f"Skipping user fetch from {len(skipped_gitlab_groups)} GitLab group(s)/project(s)."
                )
                for ns in sorted(missing_namespaces):
                    logging.info(
                        f"  - Namespace '{ns}' does not exist. "
                        f"Enable KUBERNETES_AUTO_CREATE or create it manually."
                    )
                logging.info(f"Skipped GitLab groups/projects: {', '.join(sorted(skipped_gitlab_groups))}")
            
            if filtered_namespaces:
                gitlab_users = self.gitlab.get_users(from_namespaces=filtered_namespaces)
                logging.info(
                    f"Fetched users from {len(filtered_namespaces)} GitLab group(s)/project(s) "
                    f"with existing Kubernetes namespaces"
                )
            else:
                gitlab_users = []
                logging.warning("No GitLab groups/projects have corresponding Kubernetes namespaces")

        # Fetch admins separately (they don't depend on namespaces)
        gitlab_admins = self.gitlab.get_admins()

        self.create_admin_role_bindings(admins=gitlab_admins)
        self.create_user_role_bindings(users=gitlab_users)
        self.kubernetes.delete_deprecated_user_role_bindings(
            users=gitlab_users
        )
        self.kubernetes.delete_deprecated_cluster_role_bindings(
            users=gitlab_admins
        )

    def create_admin_role_bindings(self, admins: list[dict[str, str]]) -> None:
        try:
            for admin in admins:
                role_binding_name = "{}_admin".format(admin["email"])
                if not self.kubernetes.check_role_binding(
                    name=role_binding_name
                ):
                    self.kubernetes.create_role_binding(
                        user=admin["email"],
                        user_id=admin["id"],
                        name=role_binding_name,
                        role_ref="admin",
                    )
        except Exception as e:
            logging.error(
                "unable to create admin role bindings :: {}".format(e)
            )

    def create_user_role_bindings(self, users: list[dict[str, Any]]) -> None:
        try:
            for user in users:
                namespace = user["namespace"]
                access_level = self.gitlab.ACCESS_LEVEL_REFERENCE[
                    user["access_level"]
                ]
                role_binding_name = "{}_{}".format(user["email"], access_level)

                if not self.kubernetes.check_role_binding(
                    name=role_binding_name, namespace=namespace
                ):
                    self.kubernetes.create_role_binding(
                        user=user["email"],
                        user_id=user["id"],
                        name=role_binding_name,
                        namespace=namespace,
                        role_ref=access_level,
                    )
        except Exception as e:
            logging.error(
                "unable to create user role bindings :: {}".format(e)
            )


def main() -> None:
    try:
        GITLAB_URL = environ.get("GITLAB_URL", None)
        GITLAB_PRIVATE_TOKEN = environ.get("GITLAB_PRIVATE_TOKEN", None)
        GITLAB_TIMEOUT = int(environ.get("GITLAB_TIMEOUT", "10"))
        GITLAB_GROUPS_SEARCH = environ.get(
            "GITLAB_GROUPS_SEARCH", "gitlab2rbac"
        ).split(",")
        GITLAB_NAMESPACE_GRANULARITY = environ.get(
            "GITLAB_NAMESPACE_GRANULARITY", "project"
        )
        GITLAB_ADMINS_GROUP = environ.get("GITLAB_ADMINS_GROUP", None)

        KUBERNETES_TIMEOUT = int(environ.get("KUBERNETES_TIMEOUT", "10"))
        KUBERNETES_AUTO_CREATE = eval(
            environ.get("KUBERNETES_AUTO_CREATE", "False")
        )
        KUBERNETES_LOAD_INCLUSTER_CONFIG = eval(
            environ.get("KUBERNETES_LOAD_INCLUSTER_CONFIG", "False")
        )

        GITLAB2RBAC_FREQUENCY = int(environ.get("GITLAB2RBAC_FREQUENCY", "60"))
        GITLAB_USERNAME_IGNORE_LIST = environ.get(
            "GITLAB_USERNAME_IGNORE_LIST", ""
        ).split(",")
        GITLAB_GROUPS_IGNORE_LIST = environ.get(
            "GITLAB_GROUPS_IGNORE_LIST", "lost-and-found"
        ).split(",")
        
        GITLAB_NAMESPACE_MAPPING = {}
        namespace_mapping_str = environ.get("GITLAB_NAMESPACE_MAPPING", "")
        if namespace_mapping_str:
            try:
                raw_mapping = json.loads(namespace_mapping_str)
                for gitlab_path, k8s_namespaces in raw_mapping.items():
                    if isinstance(k8s_namespaces, list):
                        GITLAB_NAMESPACE_MAPPING[gitlab_path] = k8s_namespaces
                    else:
                        logging.error(f"Invalid value type for {gitlab_path}: expected list of strings, got {type(k8s_namespaces)}")
                        raise ValueError(f"All values in GITLAB_NAMESPACE_MAPPING must be arrays")
                logging.info(f"Loaded namespace mapping: {GITLAB_NAMESPACE_MAPPING}")
            except json.JSONDecodeError as e:
                logging.error(f"Failed to parse GITLAB_NAMESPACE_MAPPING: {e}")
                logging.error("Expected JSON format, e.g.: '{\"team-data/spark\": [\"spark-operator\", \"spark\"]}'")
            except ValueError as e:
                logging.error(f"Invalid GITLAB_NAMESPACE_MAPPING format: {e}")

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
                namespace_granularity=GITLAB_NAMESPACE_GRANULARITY,
                admins_group=GITLAB_ADMINS_GROUP,
                username_ignore_list=GITLAB_USERNAME_IGNORE_LIST,
                groups_ignore_list=GITLAB_GROUPS_IGNORE_LIST,
                namespace_mapping=GITLAB_NAMESPACE_MAPPING,
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
            sleep(GITLAB2RBAC_FREQUENCY)
    except Exception as e:
        logging.error("{}".format(e))
        exit(1)


if __name__ == "__main__":
    main()
