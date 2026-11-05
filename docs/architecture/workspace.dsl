/*
 * Linux Hello — C4 workspace (System Context, Container, Component)
 * Source notes: docs/architecture/ (Arc42 sections, README.md)
 * Status: draft, UNTESTED — validate with the Structurizr CLI before use.
 * Date: 2026-10-27
 */
workspace "Linux Hello" "Biometric- and PIN-gated passkeys and secrets for the Linux desktop" {

    model {
        user = person "Desktop user" "Signs in to the session, websites and apps; enrols methods"
        admin = person "Administrator" "Authorises a trust-chain reset"

        linuxHello = softwareSystem "Linux Hello" "PIN-rooted, biometric-unlocked credential layer integrating upstream Linux components" {

            agent = container "Linux Hello Agent" "Unlock state, auth state, routing policy, PIN, enrolment and reset orchestration" "Rust daemon, D-Bus" {
                dbusApi = component "D-Bus API" "io.github.LinuxHello.Agent1; verifies peer credentials of every caller" "zbus"
                unlockState = component "Unlock State Manager" "Session unlock, expiry and re-prompt rules; state proven by TPM policy sessions, not flags" "Rust"
                authState = component "Auth State Publisher" "Signals MethodsAvailable, ActiveMethod, State, Result per prompt (UX1-UX4)" "zbus signals"
                policyEngine = component "Routing Policy Engine" "Merges default, user and admin layers; answers allowed methods per context, provider and prompt level per relying party, PIN rules; fails closed on unparseable policy" "Rust"
                pinManager = component "PIN Manager" "Change PIN in place, PIN rules, lockout status (UX7b)" "Rust"
                enrolment = component "Enrolment Orchestrator" "First-run PIN, root key creation, second-credential prompts (UX8)" "Rust"
                resetCoord = component "Reset Coordinator" "Destructive reset per ADR-0003 (LH-1)" "Rust"
                auditLog = component "Audit Logger" "Structured journald events for every unlock, sign, PIN change and reset" "Rust"
            }

            pamModule = container "pam_linuxhello" "Parallel face, fingerprint and PIN authentication" "Rust cdylib, Linux-PAM" {
                pamEntry = component "PAM Entry Points" "pam_sm_authenticate and pam_sm_open_session" "Rust FFI"
                methodOrch = component "Method Orchestrator" "Runs face, fingerprint and PIN in parallel; first success wins; cancels the rest (UX3)" "Rust, async"
                pinVerifier = component "PIN Verifier" "Satisfies TPM2 auth on the root key; TPM anti-hammering applies" "Rust"
                faceClient = component "Face Client" "Requests a face match from Howdy" "Rust"
                fingerClient = component "Fingerprint Client" "Requests a verify from fprintd" "zbus"
                agentNotifier = component "Agent Notifier" "Reports method state and session unlock to the Agent" "zbus"
            }

            tpmProvider = container "TPM Credential Provider" "Device-bound passkeys under the per-user TPM root key" "Rust daemon, credentialsd Provider API" {
                tpmProviderApi = component "Provider API Adapter" "Implements the credentialsd provider interface" "zbus"
                credStore = component "Credential Index" "Maps relying party and credential ID to TPM key handles; no private material" "Rust"
                tpmKeys = component "TPM Key Service" "Root key, auth change, child keys, policy sessions, signing" "Rust"
                tpmFfi = component "TPM FFI" "The only crate allowed unsafe code" "tss-esapi"
            }

            kpxcBridge = container "KeePassXC Provider Bridge" "Portable passkeys from KeePassXC" "Rust daemon, credentialsd Provider API" {
                kpxcProviderApi = component "Provider API Adapter" "Implements the credentialsd provider interface" "zbus"
                kpxcClient = component "KeePassXC Protocol Client" "Encrypted browser-protocol channel to KeePassXC" "Rust, NaCl box"
            }

            plasma = container "Plasma Integration" "Prompts, greeter and lock-screen integration, enrolment and settings" "Rust/cxx-qt, QML, KCM" {
                authPrompt = component "Auth Prompt QML Component" "Shared method indicator and switcher; renders Agent auth state (UX1-UX5)" "QML"
                promptUi = component "Prompt UI" "In-session user-presence and provider-choice dialogs, outside the calling app" "QML, portal backend"
                greeterTheme = component "Greeter and Lock Screen Integration" "Embeds the shared prompt in the login manager and lock screen" "QML"
                kcm = component "Linux Hello Settings Module" "Interim settings page: methods, policy (UX7a)" "KCM, QML"
                faceEnrol = component "Face Enrolment Module" "RGB preview, IR-driven guidance overlay, capture, test, delete (UX6, UX6a)" "QML, Rust"
                pinSettings = component "PIN Settings" "Change PIN, rules, lockout status, forgot-PIN link (UX7b)" "QML"
                wizard = component "Enrolment Wizard" "First run: PIN, then optional face and fingerprint (UX8)" "QML"
                usersKcmPatch = component "Users Page Entries" "Face and PIN entries beside fingerprint; upstream contribution to plasma-desktop" "QML patch"
            }

            cli = container "linuxhello-ctl" "Enrol, change PIN, reset, inspect" "Rust CLI" {
                cliCommands = component "Command Parser" "enrol, pin change, reset, policy show" "clap"
                cliAgentClient = component "Agent Client" "Calls the Agent D-Bus API" "zbus"
            }

            policyStore = container "User Policy" "User layer: ~/.config/linuxhello/policy.toml" "TOML" "Data"
            adminPolicyStore = container "Admin Policy" "Admin layer: /etc/linuxhello/policy.d/*.toml, root-owned; locked keys win" "TOML" "Data"

            secProfiles = container "Security Profiles" "Confinement and detection shipped with Linux Hello" "AppArmor, Tetragon, alert rules" {
                aaProfiles = component "AppArmor Profiles" "One enforce profile per daemon and CLI; units refuse to start unconfined" "AppArmor"
                tetraPolicies = component "Tetragon TracingPolicies" "Optional: TPM access, policy and PAM writes, ptrace, network Sigkill" "Tetragon YAML"
                alertRules = component "Alert Rules" "Alerts on Tetragon events and audit log entries" "LogQL"
            }
        }

        credentialsd = softwareSystem "credentialsd" "Linux Credentials portal and broker (LGPL-3.0)" "External"
        portal = softwareSystem "xdg-desktop-portal" "Desktop portal framework" "External"
        keepassxc = softwareSystem "KeePassXC" "Password manager holding portable passkeys (GPL)" "External"
        fprintd = softwareSystem "fprintd" "Fingerprint daemon (GPL)" "External"
        howdy = softwareSystem "Howdy" "IR face recognition; match, enrol, test (MIT)" "External"
        linuxPam = softwareSystem "Linux-PAM" "Pluggable authentication framework" "External"
        tpm = softwareSystem "TPM 2.0" "Kernel resource manager /dev/tpmrm0" "External"
        camera = softwareSystem "Camera via PipeWire" "RGB feed for preview only" "External"
        secretService = softwareSystem "Secret Service (KWallet)" "Token and secret storage" "External"
        loginManager = softwareSystem "Plasma login manager" "Graphical login" "External"
        lockScreen = softwareSystem "kscreenlocker" "Plasma lock screen" "External"
        systemSettings = softwareSystem "KDE System Settings" "Hosts KCMs; Users page with fingerprint enrolment" "External"
        browsers = softwareSystem "Browsers" "Firefox, Chromium" "External"
        nativeApps = softwareSystem "Native and Electron apps" "e.g. Claude Desktop" "External"
        relyingParties = softwareSystem "Relying parties" "Websites and identity providers" "External"
        apparmor = softwareSystem "AppArmor" "Kernel LSM, mandatory access control" "External"
        tetragon = softwareSystem "Tetragon" "eBPF runtime security (optional)" "External"
        journald = softwareSystem "systemd-journald" "System log" "External"
        logStack = softwareSystem "Log stack" "e.g. Alloy, Loki, Grafana" "External"
        mgmt = softwareSystem "Device management" "Future: delivers admin policy, as Intune does" "External"

        # People
        user -> loginManager "Signs in"
        user -> lockScreen "Unlocks"
        user -> browsers "Signs in to websites"
        user -> nativeApps "Uses"
        user -> systemSettings "Manages sign-in methods"
        user -> promptUi "Confirms, switches method"
        user -> wizard "Enrols on first run"
        admin -> cliCommands "Authorises reset"

        # External to external (context only)
        browsers -> credentialsd "WebAuthn requests" "D-Bus portal"
        nativeApps -> credentialsd "WebAuthn requests" "D-Bus portal"
        nativeApps -> secretService "Stores tokens" "Secret Service API"
        browsers -> relyingParties "WebAuthn ceremonies" "HTTPS"
        credentialsd -> portal "Exposed through"
        loginManager -> linuxPam "Authenticates via"
        lockScreen -> linuxPam "Authenticates via"

        # KDE integration
        loginManager -> greeterTheme "Loads prompt" "QML"
        lockScreen -> greeterTheme "Loads prompt" "QML"
        greeterTheme -> authPrompt "Embeds"
        promptUi -> authPrompt "Embeds"
        authPrompt -> dbusApi "Subscribes to auth state, selects method" "D-Bus"
        systemSettings -> kcm "Hosts" "KCM"
        systemSettings -> usersKcmPatch "Shows entries on Users page"
        usersKcmPatch -> faceEnrol "Opens"
        usersKcmPatch -> pinSettings "Opens"
        kcm -> faceEnrol "Opens"
        kcm -> pinSettings "Opens"
        kcm -> dbusApi "Reads and writes settings" "D-Bus"
        kcm -> policyStore "Writes user policy" "TOML"
        wizard -> dbusApi "Starts enrolment" "D-Bus"
        wizard -> systemSettings "Hands off fingerprint enrolment to Users page"
        faceEnrol -> camera "Reads RGB preview (display only)" "PipeWire camera portal"
        faceEnrol -> howdy "Enrol, test, delete; IR detection events"
        pinSettings -> dbusApi "Change PIN, lockout status" "D-Bus"
        credentialsd -> promptUi "User-presence and choice prompts" "Portal backend"
        promptUi -> dbusApi "Reads routing decision, authenticates" "D-Bus"

        # PAM module
        linuxPam -> pamEntry "Loads module" "PAM stack"
        pamEntry -> methodOrch "Authenticate"
        methodOrch -> pinVerifier "PIN path"
        methodOrch -> faceClient "Face path"
        methodOrch -> fingerClient "Fingerprint path"
        methodOrch -> agentNotifier "Method state and result"
        pinVerifier -> tpm "TPM2 policy auth" "TCTI device"
        faceClient -> howdy "Match request"
        fingerClient -> fprintd "Verify" "D-Bus"
        agentNotifier -> dbusApi "Auth state, session unlocked" "D-Bus"

        # Agent
        dbusApi -> unlockState "Unlock queries"
        dbusApi -> authState "State updates"
        dbusApi -> policyEngine "Routing queries"
        dbusApi -> pinManager "PIN requests"
        dbusApi -> enrolment "Enrol requests"
        dbusApi -> resetCoord "Reset requests"
        policyEngine -> policyStore "Reads" "TOML"
        pinManager -> tpmKeys "Change root key auth" "D-Bus"
        enrolment -> tpmKeys "Create root key" "D-Bus"
        resetCoord -> tpmKeys "Destroy root key" "D-Bus"
        resetCoord -> linuxPam "Verifies account password" "PAM conversation"
        unlockState -> auditLog "Events"
        pinManager -> auditLog "Events"
        resetCoord -> auditLog "Events"

        # Providers
        credentialsd -> tpmProviderApi "Provider calls" "D-Bus"
        tpmProviderApi -> dbusApi "Checks unlock and policy" "D-Bus"
        tpmProviderApi -> credStore "Looks up credentials"
        tpmProviderApi -> tpmKeys "Sign assertion"
        tpmKeys -> tpmFfi "ESAPI calls"
        tpmFfi -> tpm "Commands" "/dev/tpmrm0"
        credentialsd -> kpxcProviderApi "Provider calls" "D-Bus"
        kpxcProviderApi -> dbusApi "Checks unlock and policy" "D-Bus"
        kpxcProviderApi -> kpxcClient "Get or create passkey"
        kpxcClient -> keepassxc "Browser protocol" "Unix socket"

        # Policy
        policyEngine -> adminPolicyStore "Reads; locked keys win" "TOML"
        pinManager -> policyEngine "PIN rules"
        methodOrch -> dbusApi "Allowed methods for context" "D-Bus"
        admin -> adminPolicyStore "Writes admin policy"
        mgmt -> adminPolicyStore "Delivers admin policy (future)"

        # Confinement and monitoring
        aaProfiles -> apparmor "Loaded into (enforce)"
        apparmor -> agent "Confines"
        apparmor -> tpmProvider "Confines"
        apparmor -> kpxcBridge "Confines"
        apparmor -> cli "Confines"
        tetraPolicies -> tetragon "Loaded into"
        tetragon -> logStack "Security events"
        auditLog -> journald "Audit events"
        journald -> logStack "Shipped by Alloy"
        alertRules -> logStack "Loaded into"

        # CLI
        cliCommands -> cliAgentClient "Invokes"
        cliAgentClient -> dbusApi "Calls" "D-Bus"
    }

    views {
        systemContext linuxHello "Context" {
            include *
            autoLayout lr
        }
        container linuxHello "Containers" {
            include *
            autoLayout lr
        }
        component agent "Agent" {
            include *
            autoLayout lr
        }
        component pamModule "PAM" {
            include *
            autoLayout lr
        }
        component tpmProvider "TPMProvider" {
            include *
            autoLayout lr
        }
        component kpxcBridge "KeePassXCBridge" {
            include *
            autoLayout lr
        }
        component plasma "Plasma" {
            include *
            autoLayout lr
        }
        component cli "CLI" {
            include *
            autoLayout lr
        }
        component secProfiles "SecurityProfiles" {
            include *
            autoLayout lr
        }
        styles {
            element "Person" {
                shape person
            }
            element "External" {
                background #999999
                color #ffffff
            }
            element "Data" {
                shape cylinder
            }
        }
    }
}
