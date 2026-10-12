# captive-autologin

Fa il login automatico ai captive portal Wi-Fi (università, hotel, uffici, aeroporti...) e ti tiene connesso. Si basa sulla struttura della pagina, non su script specifici di una rete. Solo libreria standard di Python; disponibile come `.deb`, `.dmg` e `.exe`.

[English](README.md)

> ## ⚠️ Sicurezza: come vengono inviate le credenziali
>
> Il Wi-Fi di un captive portal è una rete locale e non fidata, e molti portali usano certificati autofirmati o HTTP semplice. Per questo captive-autologin **tenta sempre prima la via sicura**:
>
> 1. **Tentativo sicuro (sempre):** HTTPS con verifica completa del certificato. Un form su HTTP semplice viene prima ritentato su HTTPS verificato. Se la verifica fallisce l'handshake si interrompe e **non viene inviato nulla**.
> 2. **Fallback insicuro (opzionale, spento di default):** solo se attivi `allow_insecure_fallback`, e solo dopo che il passo 1 è fallito, la stessa richiesta viene ripetuta **senza verifica del certificato**, o in HTTP semplice se il portale non offre altro. Chiunque sulla rete potrebbe leggere la password.
>
> ```sh
> captive-autologin config set allow_insecure_fallback true   # oppure: captive-autologin install --insecure-fallback
> captive-autologin config set allow_insecure_fallback false  # per spegnerlo
> ```
>
> Anche con il fallback attivo le credenziali non vengono mai inviate a un host *diverso* da quello che ha servito il form, a meno che abbia un certificato HTTPS valido. I portali che chiedono solo di accettare i termini (senza password) funzionano anche senza fallback.

## Cosa gestisce

Redirect HTTP / meta refresh / JavaScript, campi nascosti e **token CSRF**, **checkbox dei termini** (in più lingue, "ricordami" resta intatto), portali click-through, portali a più passaggi, nomi di campo insoliti (`field_map`, `extra_fields`) e portali solo-JS (`login_url`). I **captcha** (reCAPTCHA, hCaptcha, Turnstile, immagine) vengono rilevati ma **non risolti**: il programma non invia mai un form con un captcha senza risposta. Puoi rispondere tu con `captive-autologin login --interactive`, oppure indicare un tuo programma in `captcha_command` (JSON su stdin, risposta su stdout; vedi README inglese).

## Installazione

Dalla pagina [Releases](../../releases): `.deb` (`sudo apt install ./captive-autologin_*_all.deb`), `.dmg` (doppio clic su `Install.command`), `.exe` (eseguilo e segui le domande). Poi `captive-autologin install`.

Installazione da remoto/headless: `printf '%s\n' "$PASSWORD" | captive-autologin install --username me --password-stdin` e, su Linux, `loginctl enable-linger "$USER"`.

Se un portale non funziona: `captive-autologin inspect` mostra cosa vede il programma (segreti mascherati), utile da allegare a una issue.
