# Graphical User Interface

The proxy exposes a built‑in GUI that lets you modify the running configuration from your browser. Once the server is started you can open `http://localhost:8080/ui/` to access it.

## Pages

The sidebar provides links to several pages:

- **General settings** – inspect existing headers, add or delete headers for all clients or for a specific client and change the current log level.
- **Analytics** – enable or disable traffic analysis and view the top visited domains in real time when analysis is active.
- **Identity** – set the proxy name and identifier which are sent upstream using the `X-Proxy-Name` and `X-Proxy-Id` headers.
- **Authentication** – turn basic authentication on or off and update the credentials stored in the database.

The main page also lists currently connected clients and updates the count using server sent events.

## Running

Build and run the proxy as described in the [README](../README.md). The GUI is served on the same address as the proxy under the `/ui/` path. If HTTPS is enabled it will also be available on the HTTPS port.

