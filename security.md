# Security Controls Map
This is a diagram which depicts how security works in pravega. (need more help for this) 
# Authentication
This section describes the various default settings and configuration options for how users or processes authenticate to the product subsystems.
Pravega supports pluggable authentication and authorization, The custom implementation performs the implementation of the AuthHandler interface, Administrators and users are allowed to implement their own Authorization/Authentication plugins. Multiple plugins of such kind can exist together. The implementation of plugin follows the Java Service Loader approach. The required Jars for the custom implementation needs to be located in the CLASSPATH to enable the access for Pravega Controller for implementation.
## Login Security Settings 
Login security including the topics of login banners, usually presenting legal disclaimers and other usage and privacy policies, failed login behaviour, and account lockout options. (need more help for this)
### 1)Logon Banner configuration
(need to tell about privacy policies)
### 2)Failed Login Behavior
(need to tell about failed login behaviour, no. of failed login steps before the exit behaviour 
is triggered, account lockout steps)
### 3)Emergency user lockout
(users or role which can generate and remove emergency lockout behaviour, description of this behaviour, how to lock out one or more users etc)
## Authentication Types and Setup
Pravega supports pluggable authentication and authorization (referred to as auth for short). For details please see [Pravega Authentication](https://github.com/pravega/pravega/blob/master/documentation/src/docs/auth/auth-plugin.md).

By default, the PasswordAuthHandler plugin is installed on the system.
To use the default `PasswordAuthHandler` plugin for `auth`, the following steps can be followed:

1. Create a file containing `<user>:<password>:<acl>;` with one line per user.
Delimiter should be `:` with `;` at the end of each line.
Use the   [PasswordCreatorTool](https://github.com/pravega/pravega/blob/master/controller/src/test/java/io/pravega/controller/auth/PasswordFileCreatorTool.java) to create a new file with the password encrypted.
Use this file when creating the secret in next step.

Sample encrypted password file:
```
$ cat userdata.txt
admin:353030303a633132666135376233353937356534613430383430373939343839333733616463363433616532363238653930346230333035393666643961316264616661393a3639376330623663396634343864643262663335326463653062613965336439613864306264323839633037626166663563613166333733653631383732353134643961303435613237653130353633633031653364366565316434626534656565636335663666306465663064376165313765646263656638373764396361:*,READ_UPDATE;
```

2. Create a kubernetes secret with this file:

```
$ kubectl create secret generic password-auth \
  --from-file=./userdata.txt \
```

Ensure secret is created:

```
$ kubectl describe secret password-auth

Name:         password-auth
Namespace:    default
Labels:       <none>
Annotations:  <none>

Type:  Opaque

Data
====
userdata.txt:  418 bytes
```

3. Specify the secret names in the `authentication` block and these parameters in the `options` block.

```
apiVersion: "pravega.pravega.io/v1alpha1"
kind: "PravegaCluster"
metadata:
  name: "example"
spec:
  authentication:
    enabled: true
    passwordAuthSecret: password-auth
...
  pravega:
    options:
      controller.auth.enabled: "true"
      controller.auth.userPasswordFile: "/etc/auth-passwd-volume/userdata.txt"
      controller.auth.tokenSigningKey: "secret"
      autoScale.authEnabled: "true"
      autoScale.tokenSigningKey: "secret"
      pravega.client.auth.token: "YWRtaW46MTExMV9hYWFh"
      pravega.client.auth.method: "Basic"

...
```

`pravega.client.auth.method` and `pravega.client.auth.token` represent the auth method and token to be used for internal communications from the Segment Store to the Controller.
If you intend to use the default auth plugin, these values are:
```
pravega.client.auth.method: Basic
pravega.client.auth.token: Base64 encoded value of <username>:<pasword>,
```
where username and password are credentials you intend to use.

Note that Pravega operator uses `/etc/auth-passwd-volume` as the mounting directory for secrets.


## User and Credential Management
### 1)Pre-Loaded Accounts
(Describe default/pre-loaded accounts and their purpose within the product or subsystem)
### 2)Default Credentials
(Describe default/pre-loaded credentials)
### 3)How To Disable Local Accounts	
(Describe how to disable or remove local accounts.)
### 4)Managing Credentials
(Describe options for managing credentials within the product.)
### 5)Securing Credentials
(Describe settings for security local credentials)
### 6)Password Complexity
(Describe customer options for creating password complexity and strength rules, including any limitations.)

## Authentication to external systems
### 1)Configuring Remote Connections
(How to configure a connection or integration to an external system)
### 2)Controlling Access to Remote Systems
(Access control options for external systems accessing the product or subsystem)
### 3)Remote Component Authentication
(How to provide credentials to use to authenticate to the external system)
### 4)Credential Security
(Options for securing credentials used to connect to remote systems)

# Authorization
## General authorization settings 
### 1)Configuring Authorization Rules
(Describe how to configure authorization for users or processes)
### 2)Default Authorizations
(Default account privilege assignments)
### 3)External Authorization Associations
(How to connect authorization to LDAP or AD-based subjects)
### 4)Entitlement Export
(Describe how a user would generate a report of authorizations)
### 5)Actions Not Requiring Authorization
(Describe actions which may be allowed without explicit authorization

## Role-Based Access Control (RBAC) 
## Setting up RBAC for Pravega operator

### Use non-default service accounts

You can optionally configure non-default service accounts for the Bookkeeper, Pravega Controller, and Pravega Segment Store pods.

For BookKeeper, set the `serviceAccountName` field under the `bookkeeper` block.

```
...
spec:
  bookkeeper:
    serviceAccountName: bk-service-account
...
```

For Pravega, set the `controllerServiceAccountName` and `segmentStoreServiceAccountName` fields under the `pravega` block.

```
...
spec:
  pravega:
    controllerServiceAccountName: ctrl-service-account
    segmentStoreServiceAccountName: ss-service-account
...
```

If external access is enabled in your Pravega cluster, Segment Store pods will require access to some Kubernetes API endpoints to obtain the external IP and port. Make sure that the service account you are using for the Segment Store has, at least, the following permissions.

```
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: pravega-components
  namespace: "pravega-namespace"
rules:
- apiGroups: ["pravega.pravega.io"]
  resources: ["*"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get"]
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: pravega-components
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get"]
```

Replace the `namespace` with your own namespace.

### Installing on a Custom Namespace with RBAC enabled

Create the namespace.

```
$ kubectl create namespace pravega-io
```

Update the namespace configured in the `deploy/role_binding.yaml` file.

```
$ sed -i -e 's/namespace: default/namespace: pravega-io/g' deploy/role_binding.yaml
```

Apply the changes.

```
$ kubectl -n pravega-io apply -f deploy
```

Note that the Pravega operator only monitors the `PravegaCluster` resources which are created in the same namespace, `pravega-io` in this example. Therefore, before creating a `PravegaCluster` resource, make sure an operator exists in that namespace.

```
$ kubectl -n pravega-io create -f example/cr.yaml
```

```
$ kubectl -n pravega-io get pravegaclusters
NAME      AGE
pravega   28m
```

```
$ kubectl -n pravega-io get pods -l pravega_cluster=pravega
NAME                                          READY     STATUS    RESTARTS   AGE
pravega-bookie-0                              1/1       Running   0          29m
pravega-bookie-1                              1/1       Running   0          29m
pravega-bookie-2                              1/1       Running   0          29m
pravega-pravega-controller-6c54fdcdf5-947nw   1/1       Running   0          29m
pravega-pravega-segmentstore-0                1/1       Running   0          29m
pravega-pravega-segmentstore-1                1/1       Running   0          29m
pravega-pravega-segmentstore-2                1/1       Running   0          29m
```
# Network security
### 1)Network Exposure
### 2)Communication Security Settings
### 3)Firewall Settings
