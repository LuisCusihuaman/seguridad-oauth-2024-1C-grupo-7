# OAuth Demo

This project demonstrates three scenarios involving OAuth Authorization Servers and Resource Servers with various vulnerabilities. It includes the option to enable or disable PKCE (Proof Key for Code Exchange) for enhanced security.

## Table of Contents

-   [Prerequisites](#prerequisites)
-   [Setup](#setup)
-   [01 Protected Resources Vulnerability](#01-protected-resources-vulnerability)
    -   [Running the Authorization Server](#running-the-authorization-server-1)
    -   [Running the OAuth Client](#running-the-oauth-client-1)
    -   [Environment Variables](#environment-variables-1)
    -   [Usage](#usage-1)
-   [02 Auth Server Vulnerability](#02-auth-server-vulnerability)
    -   [Running the Authorization Server](#running-the-authorization-server-2)
    -   [Running the OAuth Client](#running-the-oauth-client-2)
    -   [Environment Variables](#environment-variables-2)
    -   [Usage](#usage-2)
-   [03 OAuth Token Vulnerability](#03-oauth-token-vulnerability)
    -   [Running the Authorization Server](#running-the-authorization-server-3)
    -   [Running the OAuth Client](#running-the-oauth-client-3)
    -   [Environment Variables](#environment-variables-3)
    -   [Usage](#usage-3)
-   [Error Handling](#error-handling)
-   [License](#license)

## Prerequisites

-   Node.js (v14.x or later)
-   npm (v6.x or later) or pnpm (v6.x or later)

## Setup

1. Clone the repository:

    ```
    git clone https://github.com/LuisCusihuaman/seguridad-oauth-2024-1C-grupo-7
    cd seguridad-oauth-2024-1C-grupo-7
    ```

2. Install dependencies for each scenario:

    ```
    cd 01-protected-resources-vulnerability
    npm install
    cd ../02-auth-server-vulnerability
    npm install
    cd ../03-outh-token-vulnerability
    npm install
    ```

## 01 Protected Resources Vulnerability

### Running the Authorization Server

1. Navigate to the directory:

    ```
    cd 01-protected-resources-vulnerability
    ```

2. Start the authorization server:

    ```
    node authorizationServer.js
    ```

    The OAuth Authorization Server will start listening on `http://localhost:9001`.

### Running the OAuth Client

1. Navigate to the directory:

    ```
    cd 01-protected-resources-vulnerability
    ```

2. Start the OAuth client:

    ```
    node client.js
    ```

    The OAuth Client will start listening on `http://localhost:9000`.

### Environment Variables

The client application includes a feature flag to enable or disable the vulnerability.

-   **Enable vulnerable mode**:

    No need to set any environment variable, or you can explicitly set:

    ```
    export WITH_VULNERABILITY=false
    ```

-   **Disable vulnerable mode**:

    Set the `WITH_VULNERABILITY` environment variable to `true`:

    ```
    export WITH_VULNERABILITY=true
    ```

### Usage

1. Open a browser and navigate to `http://localhost:9000`.
2. Click on the "Authorize" button to initiate the OAuth flow.
3. You will be redirected to the authorization server where you will approve or deny the authorization request.
4. Upon approval, you will be redirected back to the client with an authorization code.
5. The client exchanges the authorization code for an access token.
6. Use the access token to fetch protected resources from the resource server.
7. Demonstrate the vulnerability by navigating to:

    ```
    http://localhost:9002/helloWorld?access_token=<VALID_TOKEN>&language=<script>alert('XSS')</script>
    ```

## 02 Auth Server Vulnerability

### Running the Authorization Server

1. Navigate to the directory:

    ```
    cd 02-auth-server-vulnerability
    ```

2. Start the authorization server:

    ```
    node authorizationServer.js
    ```

    The OAuth Authorization Server will start listening on `http://localhost:9001`.

### Running the OAuth Client

1. Navigate to the directory:

    ```
    cd 02-auth-server-vulnerability
    ```

2. Start the OAuth client:

    ```
    node client.js
    ```

    The OAuth Client will start listening on `http://localhost:9000`.

### Environment Variables

The client application includes a feature flag to enable or disable the vulnerability.

-   **Enable vulnerable mode**:

    No need to set any environment variable, or you can explicitly set:

    ```
    export WITH_VULNERABILITY=false
    ```

-   **Disable vulnerable mode**:

    Set the `WITH_VULNERABILITY` environment variable to `true`:

    ```
    export WITH_VULNERABILITY=true
    ```

### Usage

1. Open your favorite browser and go to:

    ```
    http://localhost:9001/authorize?client_id=oauth-client-1&redirect_uri=http://localhost:9000/callback&scope=WRONG_SCOPE
    ```

2. If vulnerable, it redirects to the client callback. In the solution, it shows a 400 status error page.

    ```javascript
    if (isVulnerable) {
    	var urlParsed = buildUrl(req.query.redirect_uri, {
    		error: "invalid_scope",
    	});
    	console.log("Redirecting to: ", urlParsed);
    	res.redirect(urlParsed);
    	return;
    } else {
    	console.log("Invalid scope requested", rscope);
    	res.status(400).render("error", {
    		error: "invalid_scope",
    		statusCode: 400,
    	});
    	return;
    }
    ```

## 03 OAuth Token Vulnerability

### Running the Authorization Server

1. Navigate to the directory:

    ```
    cd 03-outh-token-vulnerability
    ```

2. Start the authorization server:

    ```
    node authorizationServer.js
    ```

    The OAuth Authorization Server will start listening on `http://localhost:9001`.

### Running the OAuth Client

1. Navigate to the directory:

    ```
    cd 03-outh-token-vulnerability
    ```

2. Start the OAuth client:

    ```
    node client.js
    ```

    The OAuth Client will start listening on `http://localhost:9000`.

### Environment Variables

Both the client and server are insecure without PKCE. Enable PKCE by setting `WITH_VULNERABILITY` to `true`.

-   **Enable vulnerable mode**:

    Set the `WITH_VULNERABILITY` environment variable to `true` for both client and server:

    ```
    export WITH_VULNERABILITY=true
    ```

### Usage

1. Open a browser and navigate to `http://localhost:9000`.
2. Click on the "Authorize" button to initiate the OAuth flow.
3. You will be redirected to the authorization server where you will approve or deny the authorization request.
4. Upon approval, you will be redirected back to the client with an authorization code.
5. The client exchanges the authorization code for an access token.
6. Use the access token to fetch protected resources from the resource server.
7. Demonstrate the vulnerability and how PKCE secures the authorization code exchange:

    ```javascript
    if (isVulnerable) {
    	// NOT IMPLEMENTED: This is the vulnerable code, because it does not check the code_challenge
    } else {
    	if (code.request.code_challenge) {
    		console.log(
    			"Testing challenge %s against verifier %s",
    			code.request.code_challenge,
    			req.body.code_verifier
    		);

    		if (code.request.code_challenge_method == "plain") {
    			var code_challenge = req.body.code_verifier;
    		} else if (code.request.code_challenge_method == "S256") {
    			var code_challenge = base64url.fromBase64(
    				crypto
    					.createHash("sha256")
    					.update(req.body.code_verifier)
    					.digest("base64")
    			);
    		} else {
    			console.log(
    				"Unknown code challenge method",
    				code.request.code_challenge_method
    			);
    			res.status(400).json({ error: "invalid_request" });
    			return;
    		}

    		if (code.request.code_challenge != code_challenge) {
    			console.log(
    				"Code challenge did not match, expected %s got %s",
    				code.request.code_challenge,
    				code_challenge
    			);
    			res.status(400).json({ error: "invalid_request" });
    			return;
    		}
    	}
    }
    ```
