<?php

namespace CleantalkSP\SpbctWP\Scanner\Stages\SignatureAnalysis;

class SignatureAnalysisFacade
{
    public static function getLatestSignatureSubmittedTime()
    {
        return Repository::getLatestSignatureSubmittedTime();
    }

    public static function getSignaturesFromCloud($latest_signature_submitted_time)
    {
        return Repository::getSignaturesFromCloud($latest_signature_submitted_time);
    }

    public static function clearSignaturesTable()
    {
        Repository::clearSignaturesTable();
    }

    public static function addSignaturesToDb($map, $signatures)
    {
        return Repository::addSignaturesToDb($map, $signatures);
    }

    public static function thereAreSignaturesInDb()
    {
        return Repository::thereAreSignaturesInDb();
    }

    public static function addSignaturesToDbOneByOne($map, $signatures)
    {
        return Repository::addSignaturesToDbOneByOne($map, $signatures);
    }
}
