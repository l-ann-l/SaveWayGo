import { SignInResult } from "./signin-result";
import { SignInProvider } from "./signin-provider";

// Google Identity Services (GIS) - replaces the deprecated gapi.auth2 (shut down March 2023)
// See: https://developers.google.com/identity/oauth2/web/guides/migration-to-gis

declare global {
    interface Window {
        google?: {
            accounts: {
                oauth2: {
                    initTokenClient(config: GoogleTokenClientConfig): GoogleTokenClient;
                };
            };
        };
    }
}

interface GoogleTokenClientConfig {
    client_id: string;
    scope: string;
    callback: (response: GoogleTokenResponse) => void;
    error_callback?: (error: GoogleTokenError) => void;
}

interface GoogleTokenClient {
    requestAccessToken(options?: { prompt?: string }): void;
}

interface GoogleTokenResponse {
    access_token: string;
    expires_in: number;
    token_type: string;
    scope: string;
    error?: string;
}

interface GoogleTokenError {
    type: string;
    message?: string;
}

interface GoogleUserInfo {
    email?: string;
    name?: string;
    picture?: string;
    sub?: string;
}

export class GoogleProvider implements SignInProvider {

    // GIS script URL — replaces the old apis.google.com/js/api:client.js
    static readonly gisScriptUrl = "https://accounts.google.com/gsi/client";

    constructor(private clientId: string) {
    }

    signIn(): Promise<SignInResult> {
        return this.loadDependencies()
            .then(() => this.signInWithGIS());
    }

    loadDependencies(): Promise<void> {
        return this.appendGISScript();
    }

    private appendGISScript(): Promise<void> {
        if (window.google?.accounts) {
            return Promise.resolve();
        }

        return new Promise<void>((resolve, reject) => {
            const scriptEl = window.document.createElement("script");
            scriptEl.async = true;
            scriptEl.src = GoogleProvider.gisScriptUrl;
            scriptEl.onload = () => resolve();
            scriptEl.onerror = (error) => reject({ message: "Error loading Google Identity Services library", error });
            window.document.head.appendChild(scriptEl);
        });
    }

    private signInWithGIS(): Promise<SignInResult> {
        if (!window.google?.accounts) {
            return Promise.reject("Google Identity Services wasn't loaded");
        }

        return new Promise<SignInResult>((resolve, reject) => {
            const tokenClient = window.google!.accounts.oauth2.initTokenClient({
                client_id: this.clientId,
                scope: "openid email profile",
                callback: (tokenResponse: GoogleTokenResponse) => {
                    if (tokenResponse.error) {
                        reject(new Error(`Google sign-in error: ${tokenResponse.error}`));
                        return;
                    }
                    this.fetchUserInfo(tokenResponse)
                        .then(result => resolve(result))
                        .catch(err => reject(err));
                },
                error_callback: (error: GoogleTokenError) => {
                    reject(new Error(`Google sign-in failed: ${error.type} - ${error.message || ""}`));
                }
            });

            tokenClient.requestAccessToken({ prompt: "select_account" });
        });
    }

    private async fetchUserInfo(tokenResponse: GoogleTokenResponse): Promise<SignInResult> {
        try {
            const response = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
                headers: { Authorization: `Bearer ${tokenResponse.access_token}` }
            });

            if (!response.ok) {
                throw new Error(`Failed to fetch user info: ${response.statusText}`);
            }

            const userInfo = await response.json() as GoogleUserInfo;
            const expiration = new Date(Date.now() + tokenResponse.expires_in * 1000);

            return {
                email: userInfo.email ?? null,
                name: userInfo.name ?? null,
                imageUrl: userInfo.picture ?? null,
                accessToken: tokenResponse.access_token,
                accessTokenExpiration: expiration,
                provider: "Google",
                error: null,
                providerData: { tokenResponse, userInfo }
            };
        } catch (error) {
            return {
                provider: "Google",
                error: error instanceof Error ? error : new Error(String(error))
            };
        }
    }
}
