# Hands on with Snyk

## What is Snyk?

Snyk is a security scanning tool, used to find vulnerable dependencies. 

## Snyk and Docker Images

The official Docker engine integrated with Snyk, allowing you to scan images directly using the Docker CLI:

```bash

$ CVE-2021-41773 git:(master) docker scan cve-2021-41773_myproject            

Testing cve-2021-41773_myproject...
...
Organization:      ecsdcmhrpr
Package manager:   deb
Project name:      docker-image|cve-2021-41773_myproject
Docker image:      cve-2021-41773_myproject
Platform:          linux/amd64
Licenses:          enabled

Tested 146 dependencies for known issues, found 55 issues.
```

## Log in to Snyk

To start using the Snyk image scanner, you first need to authenticate with the Snyk service. This is done by running:

`