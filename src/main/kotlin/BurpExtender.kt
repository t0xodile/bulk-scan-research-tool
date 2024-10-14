package burp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ThreadPoolExecutor


class BurpExtender: BurpExtension, IExtensionStateListener, IBurpExtender {
    //Stuff we need to access outside of this class
    companion object {
        internal val configSettings = SettingsBox()
    }

    val name: String = "t0xodile's Research Tool"
    private val version = "0.01"
    var unloaded: Boolean = false
    val hostsToSkip: ConcurrentHashMap<String, Boolean> = BulkScan.hostsToSkip
    private lateinit var taskEngine: ThreadPoolExecutor

    //Grab our MontoyaApi instance. You can reach this using Utilities.montoyaApi from now on.
    override fun initialize(api: MontoyaApi) {
        Utilities.montoyaApi = api
    }


    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {

        Utilities(callbacks, HashMap(), name)

        //Custom settings that we want to add.
        configSettings.register("Print Responses", false, "Prints the response to console.")


        callbacks.setExtensionName(name)
        BulkScanLauncher(BulkScan.scans)
        callbacks.registerExtensionStateListener(this);

        //Scans
        BasicCheck("Basic Check")


        BulkUtilities.out("Loaded " + name + " v" + version);
    }

    //ON unload, kill everything in the queue!
    override fun extensionUnloaded() {
        BulkUtilities.log("Aborting all attacks");
        BulkUtilities.unloaded.set(true);
        taskEngine.queue.clear();
        taskEngine.shutdown();
    }

}