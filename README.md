# gitlab2rbac
`gitlab2rbac` synchronizes Kubernetes cluster user permissions with those defined in GitLab, ensuring consistent access controls across both platforms.

This tool takes [GitLab Permissions](https://docs.gitlab.com/ee/user/permissions.html) on a project level and generates corresponding [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) objects within Kubernetes.

![graph](graph.png)

## Installation
### Requirements
Before anything else, `gitlab2rbac` requires:

* [RBAC is enabled on your Kubernetes cluster](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
* [GitLab API v4 support is available](https://docs.gitlab.com/ee/api/rest/)

### Deploy with helm

```
helm install gitlab2rbac /path/to/chart/gitlab2rbac --create-namespace gitlab2rbac --set data.GITLAB_URL=<your_gitlab_instance_url>,data.GITLAB_PRIVATE_TOKEN=<your_private_token>,data.KUBERNETES_LOAD_INCLUSTER_CONFIG=True
```

or

### Configuration
`gitlab2rbac` requires a namespace, cluster roles and cluster role bindings. You can create these by executing:

```sh
$ kubectl apply -f https://raw.githubusercontent.com/numberly/gitlab2rbac/master/deploy/configuration.yaml
```

Next, create a [ConfigMap](https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/) containing the necessary configuration:

```sh
cat <<EOF | kubectl create -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: gitlab2rbac
  namespace: gitlab2rbac
data:
  GITLAB_URL: https://{{ your GitLab instance URL }}
  GITLAB_PRIVATE_TOKEN: {{ your GitLab private token }}
  KUBERNETES_LOAD_INCLUSTER_CONFIG: "True"
EOF
```

### Deployment
Finally, just apply the manifest:

```sh
$ kubectl apply -f https://raw.githubusercontent.com/numberly/gitlab2rbac/master/deploy/gitlab2rbac.yaml
```

This deployment will run `gitlab2rbac` in the `gitlab2rbac` namespace. The manifest includes:

* A deployment resource, which acts as the cluster-wide controller for RBAC policies.
* A service account and associated RBAC permissions required for the controller to operate.

## Running locally
### Requirements
To run `gitlab2rbac` locally, you need:

* A Kubernetes environment, such as one set up with [minikube](https://minikube.sigs.k8s.io/docs/).
* Python 3 (Python 2 might work but is not supported).
* Virtualenv (recommended for environment isolation).

### Setup
Even if `gitlab2rbac` doesn't run inside Kubernetes, it needs a cluster with existing cluster roles. Create them with:

```sh
$ kubectl apply -f https://raw.githubusercontent.com/numberly/gitlab2rbac/master/deploy/configuration.yaml
```

Then you can clone the repository, install the dependencies and run `gitlab2rbac`:

```sh
$ git clone https://github.com/numberly/gitlab2rbac.git
$ cd gitlab2rbac
$ virtualenv .venv && source .venv/bin/activate
(.venv) $ pip install -r requirements.txt
(.venv) $ GITLAB_URL={{ your GitLab instance URL }} GITLAB_PRIVATE_TOKEN={{ your GitLab private token }} python gitlab2rbac.py
```

## Matrix GitLab role & Kubernetes resources
**[here](./docs/matrix.md)**

## Advanced configuration
`gitlab2rbac` supports multiple environment variables for advanced configuration:

| Flag                                | Description                                                                 | Default		|
|:------------------------------------|:----------------------------------------------------------------------------|:------------------|
|`GITLAB2RBAC_FREQUENCY`              |Update interval in seconds.                                                  |60			|
|`GITLAB_ADMINS_GROUP`                |Base your k8s admins on GitLab namespace (None means GitLab administrators). |None		|
|`GITLAB_GROUPS_IGNORE_LIST`	      |Groups to ignore (separated by commas, default value is "lost-and-found"	    |lost-and-found	|
|`GITLAB_GROUPS_SEARCH`               |Limit to those groups (separated by commas, empty means all groups).         |gitlab2rbac 	|
|`GITLAB_NAMESPACE_GRANULARITY`       |Whether to get permissions from GitLab projects or groups.                   |project     	|
|`GITLAB_PRIVATE_TOKEN`               |Configure gitlab API token.                                                  |            	|
|`GITLAB_USERNAME_IGNORE_LIST`	      |Gitlab users to ignore for the synchronisation				    |			|
|`GITLAB_TIMEOUT`                     |Timeout for GitLab operations, in seconds.                                   |10          	|
|`GITLAB_URL`                         |Configure gitlab API target.                                                 |            	|
|`KUBERNETES_AUTO_CREATE`             |Replicate GitLab groups/projects as Kubernetes namespaces.                   |False       	|
|`KUBERNETES_LOAD_INCLUSTER_CONFIG`   |Load configuration inside Kubernetes when gitlab2rbac runs as a pod.         |False       	|
|`KUBERNETES_TIMEOUT`                 |Timeout for Kubernetes operations, in seconds.                               |10          	|
|`SENTRY_DSN`                         |Start sentry_sdk, if set and package is installed.                           |            	|

## Kubernetes cluster compatibility

The following table outlines the compatibility between gitlab2rbac versions and Kubernetes cluster versions. Ensure that you are using the correct version of gitlab2rbac for your Kubernetes cluster to maintain stability and functionality.

:construction: not tested

:green_circle: ok

| GitLab2rbac Version   | k8s 1.25 | k8s 1.26 | k8s 1.27 | k8s 1.28 | k8s 1.29 | k8s 1.30 | k8s 1.31 |
|-------------------|:-----------:|:-----------:|:-----------:|:-----------:|:-----------:|:-----------:|:-----------:|
| **0.2.4**    |      :green_circle:       |      :green_circle:       |      :green_circle:      |      :green_circle:      |      :green_circle:        |      :green_circle:        |      :green_circle:        |

## License
MIT
