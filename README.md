# Thesis
## Prerequisiti
* Sistema Operativo macOS
  * Frida (pip install frida)
  * frida-tools (pip install frida-tools)
  * [Appium Desktop](https://github.com/appium/appium-desktop/releases)
  * xCode per la configurazione di WDA incluso in Appium Desktop: vedere il capitolo "[full manual configuration di questa guida](https://appium.io/docs/en/drivers/ios-xcuitest-real-devices/)"
* dispositivo fisico con Jailbreak attivo
  * [Frida installato da Cydia](https://frida.re/docs/ios/)
## Istruzioni
1. Connettere il dispositivo di test tramite USB al Mac mantenendolo sempre con lo schermo acceso (in iOS 14: *impostazini>Schermo e luminosità>Blocco automatico e selezionare 'mai'*)
2. Avviare Appium Desktop assicurandosi che i parametri corrispondano alla seguente immagine:
![configurazione di default appium](/docs/appium_default.png)
3. Modificare i parametri di configurazione richiesti in *caps.json*