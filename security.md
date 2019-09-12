# Security Controls Map
Diagram which depicts how security works in pravega. (need more help for this) 
# Authentication
This section describes the various default settings and configuration options for how users or processes authenticate to the product subsystems.\
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
Pravega implement a pluggable authorization model. The authorization kicks in only with interactions with the controller through GRPC or REST. Once the request is authorized, controller generates a token. This token will be presented to the SegmentStore. Once the token is validated, SegmentStore will assume that the interactions have already been approved by the controller. The authorizer model returns whether the user is authorized as well as a string which represents the user identity.  Advantage of this will mean that we do not have authorization happening twice, once with the controller and then with segmentstore. This will also take the authorization part away from the performance critical path.

### a. Token format
Token is used to share authorization information between Pravega controller and SegmentStore. The token follows the JWT (JSON Web Token) format closely. [https://tools.ietf.org/html/rfc7519](https://tools.ietf.org/html/rfc7519) It is signed by a symmetric key shared between controller and SegmentStore. More details about how JWT tokens are signed can be found here: [https://tools.ietf.org/html/rfc7515](https://tools.ietf.org/html/rfc7515). A token consists of the resource identifier. SegmentStore has the responsibility of validating the token. It also converts the token from controller primitives (stream/scope) to SegmentStore primitives (segments). SegmentStore validates signature of this token, validates that the resource id requested matches the one specified in the token, validates the lifetime of the token and if it matches, performs the given operation.

### b. Why JWT
Jason Web Token format and implementation gives an efficient way of signing and encrypting claim based tokens. This is a widely used format and has advanced features in-built like token expiry etc which will be useful in the context of Pravega.

### c. Token lifetime and revocation
Tokens are short lived. Controller controls their lifetime using the 'exp' claim. [https://tools.ietf.org/html/rfc7519#section-4.1.4](https://tools.ietf.org/html/rfc7519#section-4.1.4). The expiration time is checked before start of a given SegmentStore operation. In case an expired token is observed, SegmentStore returns appropriate error to the client. The client can interact with controller and receive a new token after controller reauthenticates it.

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
(we need to mention the ports and protocols in use and default execution mode)
### 2)Communication Security Settings
(we need to mention Configuration options to enable endpoint validation)
### 3)Firewall Settings
(we need to mention How to configure or verify the functionality of the product’s firewall)

# Data Security
### 1)Data Storage Security Settings
(we need to mention capabilities for securing application and customer data)

### 2)Data at Rest Encryption
#### Encryption of data in Tier 1
Pravega uses Apache BookKeeper as Tier 1 implementation. Apache Bookkeeper currently does not support encryption of data written to disk.

#### Encryption of data in Tier 2¶
Pravega can work with different storage options for Tier 2. To use any specific storage option, it is necessary to implement a storage interface. We currently have the following options implemented:
HDFS
Extended S3
File system (NFS).

Pravega does not encrypt data before storing it in Tier 2. Consequently, Tier 2 encryption is only an option in the case the storage system provides it natively, and as such, needs to be configured directly in the storage system, not via Pravega.

### 3)Data in Flight Encryption
Pravega ensures that all the data in flight can be passed by applying encryption. The different channels present in data integrity section can be configured with TLS and encryption can be enabled for them.
 
### 4)Data Sanitization
(we need to mention capabilities for securely sanitizing (erasing) customer data)
### 5)Data Integrity

Client can communicate with Pravega in a more secure way using TLS. To enable this feature, you will first need to
create secrets for Controller and Segment Store to make the relevant, sensible files available to the backend pods.

```
$ kubectl create secret generic controller-tls \
  --from-file=./controller01.pem \
  --from-file=./ca-cert \
  --from-file=./controller01.key.pem \
  --from-file=./controller01.jks \
  --from-file=./password
```

```
$ kubectl create secret generic segmentstore-tls \
  --from-file=./segmentstore01.pem \
  --from-file=./ca-cert \
  --from-file=./segmentstore01.key.pem
```

Then specify the secret names in the `tls` block and the TLS parameters in the `options` block.

```
apiVersion: "pravega.pravega.io/v1alpha1"
kind: "PravegaCluster"
metadata:
  name: "example"
spec:
  tls:
    static:
      controllerSecret: "controller-tls"
      segmentStoreSecret: "segmentstore-tls"
...
  pravega:
    options:
      controller.auth.tlsEnabled: "true"
      controller.auth.tlsCertFile: "/etc/secret-volume/controller01.pem"
      controller.auth.tlsKeyFile: "/etc/secret-volume/controller01.key.pem"
      pravegaservice.enableTls: "true"
      pravegaservice.certFile: "/etc/secret-volume/segmentStore01.pem"
      pravegaservice.keyFile: "/etc/secret-volume/segmentStore01.key.pem"
...
```

Note that Pravega operator uses `/etc/secret-volume` as the mounting directory for secrets.

For more security configurations, check [here](https://github.com/pravega/pravega/blob/master/documentation/src/docs/security/pravega-security-configurations.md).

## Security Configuration Parameters in Distributed Mode

In the distributed mode, Controllers and Segment Stores are configured individually. The following sub-sections describe
their Transport Layer Security (TLS) and auth (short for authentication and authorization) parameters.


### Segment Store

|Parameter|Description|Default Value|Feature|
|---------|-------|-------------|------------|
| `pravegaservice.enableTls` | Whether to enable TLS for client-server communications. | False | TLS |
| `pravegaservice.certFile` | Path of the X.509 PEM-encoded server certificate file for the service. | Empty | TLS |
| `pravegaservice.keyFile` | Path of the PEM-encoded private key file for the service. | Empty | TLS |
| `pravegaservice.secureZK` | Whether to enable TLS for communication with Apache Zookeeper. | False | TLS |
| `pravegaservice.zkTrustStore` | Path of the truststore file in `.jks` format for TLS connections with Apache Zookeeer. | Empty | TLS |
| `pravegaservice.zkTrustStorePasswordPath` | Path of the file containing the password of the truststore used for TLS connections with Apache Zookeeper. | Empty | TLS |
| `autoScale.tlsEnabled` | Whether to enable TLS for internal communication with the Controllers. | False | TLS |
| `autoScale.tlsCertFile` | Path of the PEM-encoded X.509 certificate file used for TLS connections with the Controllers. | Empty | TLS |
| `autoScale.validateHostName` | Whether to enable hostname verification for TLS connections with the Controllers. | True | TLS |
| `autoScale.authEnabled` | Whether to enable authentication and authorization for internal communications with the Controllers. | False | Auth |
| `autoScale.tokenSigningKey` | The key used for signing the delegation tokens. | Empty | Auth |
| `bookkeeper.tlsEnabled` | Whether to enable TLS for communication with Apache Bookkeeper. | False | TLS |
| `bookkeeper.tlsTrustStorePath` | Path of the truststore file in `.jks` format for TLS connections with Apache Bookkeeper. | Empty | TLS |


### Controller

|Parameter|Details|Default Value|Feature|
|---------|-------|-------------|-------|
| `controller.auth.tlsEnabled` | Whether to enable TLS for client-server communication. | False | TLS |
| `controller.auth.tlsCertFile` | Path of the X.509 PEM-encoded server certificate file for the service. | Empty | TLS |
| `controller.auth.tlsKeyFile` | Path of the PEM-encoded private key file for the service. | Empty | TLS |
| `controller.auth.tlsTrustStore` | Path of the PEM-encoded truststore file for TLS connections with Segment Stores. | Empty | TLS |
| `controller.rest.tlsKeyStoreFile` | Path of the keystore file in `.jks` for the REST interface. | Empty | TLS |
| `controller.rest.tlsKeyStorePasswordFile` | Path of the file containing the keystore password for the REST interface. | Empty | TLS |
| `controller.zk.secureConnection` | Whether to enable TLS for communication with Apache Zookeeper| False | TLS |
| `controller.zk.tlsTrustStoreFile` | Path of the truststore file in `.jks` format for TLS connections with Apache Zookeeer. | Empty | TLS |
| `controller.zk.tlsTrustStorePasswordFile` | Path of the file containing the password of the truststore used for TLS connections with Apache Zookeeper. | Empty | TLS |
| `controller.auth.enabled` | Whether to enable authentication and authorization for clients. | False | Auth |
| `controller.auth.userPasswordFile` | Path of the file containing user credentials and ACLs, for the PasswordAuthHandler.| Empty | Auth |
| `controller.auth.tokenSigningKey` | Key used to sign the delegation tokens for Segment Stores. | Empty | Auth |


## Security Configurations in Standalone Mode

For ease of use, Pravega standalone mode abstracts away some of the configuration parameters of distributed mode. As a result, it has
fewer security configuration parameters to configure.


|Parameter|Details|Default Value|Feature|
|---------|-------|-------------|-------|
| `singlenode.enableTls` | Whether to enable TLS for client-server communications. | False | TLS |
| `singlenode.certFile` | Path of the X.509 PEM-encoded server certificate file for the server. |Empty| TLS |
| `singlenode.keyFile` | Path of the PEM-encoded private key file for the service. | Empty | TLS |
| `singlenode.keyStoreJKS` | Path of the keystore file in `.jks` for the REST interface. | Empty | TLS |
| `singlenode.keyStoreJKSPasswordFile` |Path of the file containing the keystore password for the REST interface. | Empty | TLS |
| `singlenode.trustStoreJKS` | Path of the truststore file for internal TLS connections. | Empty | TLS |
| `singlenode.enableAuth` | Whether to enable authentication and authorization for clients. |False| Auth |
| `singlenode.passwdFile` | Path of the file containing user credentials and ACLs, for the PasswordAuthHandler. |Empty| Auth |
| `singlenode.userName` | The default username used for internal communication between Segment Store and Controller. | Empty| Auth |
| `singlenode.passwd` | The default password used for internal communication between Segment Store and Controller. | Empty| Auth |

### 6)Other Data Security Features
(we need to mention Document other data security features or capabilities, when available)

# Cryptography
### 1)Cryptographic Configuration Options
(Describe capabilities and options for using cryptography in the product.)
### 2)Certified Cryptographic Modules
(Describe capabilities for use of FIPS 140-2 validated cryptographic modules and settings)
### 3)Certificate Management
(Describe settings and options for using certificates in the product)
### 4)Regulatory Information
(Provide references to export compliance and other regulatory information customers should be aware of)

# Auditing and Logging
### 1)Logs
(Describe log location(s) and usage)
### 2)Log Management
(Describe options for managing logs in the system.)
### 3)Log Protection
(Describe capabilities for securing security-sensitive log contents)
### 4)Logging Format
(Describe the format of logs, including timestamp formats, special labels or indicators, and other details customers will need to properly understand security logs.)
### 5)Alerting
(Describe features and options for generating alerts)

# Physical Security
### 1)Physical Interfaces
(Describe physical ports and interfaces)
### 2)Physical Security Options
(Describe physical security controls in place or that can be applied by customers)
### 3)Customer Service Access
(Describe necessary access to physical devices restricted for service use vs customer use)
### 4)Tamper Evidence and Resistance
(Describe mechanisms in place or that can be applied by customers to protect access to the product physically)
### 5)Statement of Volatility
(Provide a reference to or copy of any Statements of Volatility)

# Serviceability
### 1)Maintenance Aids
(Describe accounts, tools, and other functionality intended as “Maintenance Aids")
### 2)Responsible Service Use by Dell
(Describe expectations around service access by Dell)
### 3)Data Shared with Dell
(Identify the types of information transmitted to Dell via a ‘call home’ or serviceability tool that is part of the Dell product)
### 4)Security Updates and Patching
(Describe the security patching and update policy and behavior and settings that relate to this functionality (if available))
### 5)Customer Requirements for Updates
(Describe actions customers must take with respect to security updates)

# Code/Product Authenticity and Integrity
### 1)Code/Product Authenticity and Integrity
(Identify how the authenticity and integrity of the distributed product and/or its code (software and firmware) is maintained)
### 2)Code/Product Verification
(Describe how a customer can verify the authentication and integrity of the distributed product)
    
