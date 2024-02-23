<?php

namespace CleantalkSP\Common\FSWatcher\View;

abstract class Phrases
{
    abstract public function getTitle();
    abstract public function getDescription();
    abstract public function getSnapshotsPeriodDescription();
    abstract public function getExtendedTabDescription();
    abstract public function featureNotReady1();
    abstract public function featureNotReady2();
    abstract public function getCompareButtonText();
    abstract public function getCompareButtonDescription();
    abstract public function getCreateSnapshotButtonText();
    abstract public function getFirstDateLabel();
    abstract public function getSecondDateLabel();
    abstract public function getTableHeadPath();
    abstract public function getTableHeadEvent();
    abstract public function getTableHeadChangeOn();
    abstract public function getTableNoLogs();
    abstract public function getTranslations();
}
