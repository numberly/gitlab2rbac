### Role Descriptions
| Role       | Use Cases                 | Typical Examples                    |
|:----------:|:-------------------------:|:-----------------------------------:|
| Guest      | Inspiration               | Team members from other departments |
| Reporter   | Complete overview, testing| Project managers, marketing staff   |
| Developer  | Deployment, debugging     | Engineers, technical project managers |
| Maintainer | Sensitive configurations  | Lead or senior engineers            |

### RBAC Permissions Matrix
In Kubernetes, `R` and `W` correspond to API verbs:
* **Read (`R`)**: `get`, `list`, `watch`
* **Write (`W`)**: `create`, `update`, `patch`, `delete`, `deletecollection`

#### Cluster-Wide Resources
All authenticated users have access to the following cluster-wide resources:
* apiservices
* componentstatuses (deprecated in v1.19+)
* namespaces
* nodes

GitLab admins are automatically granted admin privileges in the Kubernetes cluster.

#### Workload Resources
| Resource                 | Guest | Reporter | Developer | Maintainer |
|:------------------------:|:-----:|:--------:|:---------:|:----------:|
| cronjobs                 |   R   |    R     |   R+W     |    R+W     |
| daemonsets               |   R   |    R     |   R+W     |    R+W     |
| deployments              |   R   |    R     |   R+W     |    R+W     |
| horizontalpodautoscalers |   R   |    R     |   R+W     |    R+W     |
| ingresses                |   R   |    R     |   R+W     |    R+W     |
| jobs                     |   R   |    R     |   R+W     |    R+W     |
| pods                     |   R   |    R     |   R+W     |    R+W     |
| replicasets              |   R   |    R     |   R+W     |    R+W     |
| replicationcontrollers   |   R   |    R     |   R+W     |    R+W     |
| services                 |   R   |    R     |   R+W     |    R+W     |
| statefulsets             |   R   |    R     |   R+W     |    R+W     |
| verticalpodautoscalers   |   R   |    R     |   R+W     |    R+W     |
| events                   |       |    R     |    R      |    R+W     |

#### Action-Based Resources
| Resource                     | Guest | Reporter | Developer | Maintainer |
|:----------------------------:|:-----:|:--------:|:---------:|:----------:|
| pods/log                     |       |   R+W    |   R+W     |    R+W     |
| pods/portforward             |       |   R+W    |   R+W     |    R+W     |
| deployments/rollback         |       |          |   R+W     |    R+W     |
| deployments/scale            |       |          |   R+W     |    R+W     |
| pods/attach                  |       |          |   R+W     |    R+W     |
| pods/exec                    |       |          |   R+W     |    R+W     |
| replicasets/scale            |       |          |   R+W     |    R+W     |
| replicationcontrollers/scale |       |          |   R+W     |    R+W     |
| statefulsets/scale           |       |          |   R+W     |    R+W     |

#### Setup Resources
| Resource                      | Guest | Reporter | Developer | Maintainer |
|:-----------------------------:|:-----:|:--------:|:---------:|:----------:|
| configmaps                    |   R   |    R     |   R+W     |    R+W     |
| endpoints                     |   R   |    R     |   R+W     |    R+W     |
| networkpolicies               |   R   |    R     |   R+W     |    R+W     |
| persistentvolumeclaims        |   R   |    R     |   R+W     |    R+W     |
| persistentvolumeclaims/status |   R   |    R     |   R+W     |    R+W     |
| poddisruptionbudgets          |   R   |    R     |   R+W     |    R+W     |
| poddisruptionbudgets/status   |   R   |    R     |   R+W     |    R+W     |
| serviceaccounts               |   R   |    R     |   R+W     |    R+W     |
| certificates                  |       |          |   R+W     |    R+W     |
| secrets                       |       |          |   R+W     |    R+W     |
| limitranges                   |       |          |    R      |    R+W     |
| resourcequotas                |       |          |    R      |    R+W     |
| rolebindings                  |       |          |    R      |    R+W     |
| roles                         |       |          |    R      |    R+W     |

