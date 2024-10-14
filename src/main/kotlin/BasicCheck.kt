package burp

//this is a basic scan check implementation
internal class BasicCheck(name: String?) : Scan(name) {

    //Init is a constructor in Kotlin. Import any settings you wanted outside of the global ones
    init {
        super.name
        scanSettings.importSettings(BurpExtender.configSettings)
    }

    //this is where your scan logic goes
    override fun doScan(baseReq: ByteArray, service: IHttpService): MutableList<IScanIssue> {
        val checkRequestResponse = Utilities.buildMontoyaReq(baseReq, service) //Easy way to build a montoya request so you can stop messing with the old version
        checkRequestResponse.withHeader("X-Outpost24", "Outpost24washere")

        val resp = Utilities.montoyaApi.http().sendRequest(checkRequestResponse)

        if (resp.response().body().toString().contains("Outpost24washere")) {
            report("X-Outpost24 header reflection", "The X-Outpost24 header randomly caused reflected content in the response body!", resp) //Reporing an issue is this easy too!
        }

        //Check a settings
        if (Utilities.globalSettings.getBoolean("Print Responses")) {
            BulkUtilities.out("Response was -> " + resp.response().toString())
        }

        return mutableListOf<IScanIssue>()
    }
}