## SAML OSGI bundle for dotCMS 

![Screen Shot 2020-10-16 at 11 23 22 AM](https://user-images.githubusercontent.com/934364/96277374-2e400c00-0fa2-11eb-97bc-dd564312c802.png)


### This OSGI bundle is shipped with dotCMS and can be accessed and managed using dotCMS Apps

For more information on how to configure SAML in dotCMS, see the documentation here: https://dotcms.com/docs/latest/sso-saml

### What is SAML and how it works in dotCMS?

- SAML is a protocol based on XML (Security Assertion Markup Language), do to SSO (Single Sign On)
- Users authenticate once and gain access to multiple applications without re-entering credentials.
- May handle roles and authorizations.
  
  .
- SAML could breakdown in two parts:
  - Identity Provider (IdP): This is the source of truth and it is in charge of the authentication, examples: Okta, Azure, etc.
  - Service Provider (SP): This is the app, the web site in this case dotCMS.
  
- How it works
  - Step 1: User attempts to access an SP (aka hit to dotCMS, demo.dotcms.com/dotAdmin for instance).
  - Step 2: SP redirects the user to the IdP for authentication (for instance to azure to get the login by SSO).
  - Step 3: IdP authenticates the user and creates a SAML Assertion.
  - Step 4: SAML Assertion (which is a XML) is sent back by post to the SP (dotCMS endpoint), via browser.
  - Step 5: SP validates the SAML Assertion, creates or get login the user and grants access (roles, claims, groups, etc).

![saml-flow.png](doc/images/saml-flow.png)

### Why SAML lives in core and in a plugin?

SAML code is splitted in two repositories:
- This current repository contains all the openSAML libraries and boilerplate to interact with this library, which is in charge of creating all the Metadata XML, Authentication and Logout request, and process the IDP Assertions and so on.
- The other repository is core, and contains two main things; a) the Interceptor that catches the urls to start the SSO process b) a rest endpoint which is the place where the IDP will land the Assertion when the user gets login

Note: this repository exists because open saml introduces many libraries and dependencies, similar to Tika, we want to hide these deps from the classpath, so it is the main reason to have this separated

#### Plugin code: what is in charge of?



--------
#### Change Log:
- 25.04.28: added the ability to remove the RequestedAuthnContext from the auth

