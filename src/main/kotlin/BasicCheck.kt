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

        val base = Utilities.buildMontoyaResp(request(service, baseReq)) //Easy way to build a montoya request so you can stop messing with the old version

        val checkRequest = base.request().withAddedHeader("X-Assured", "Assured")

        val checkRequestResponse = request(checkRequest, false) //Second param is Force HP1?

        if (checkRequestResponse.response().bodyToString().contains("Assured")) {
            report("X-Assured header reflection", "The X-Assured header randomly caused reflected content in the response body!", checkRequestResponse) // Reporing an issue is this easy too!
        }

        //Check a settings
        if (Utilities.globalSettings.getBoolean("Print Responses")) {
            BulkUtilities.out("Response was -> " + checkRequestResponse.response().toString())
        }

        return mutableListOf<IScanIssue>()
    }
}