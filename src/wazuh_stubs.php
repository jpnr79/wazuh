<?php
// --- Stubs for missing methods to avoid fatal errors ---
if (!method_exists('PluginWazuhAgent', 'showItems')) {
    if (!class_exists('PluginWazuhAgent')) {
        class PluginWazuhAgent {}
    }
    class PluginWazuhAgentStub extends PluginWazuhAgent {
        public function showItems() { echo '<div class="center">showItems() stub</div>'; }
    }
}
if (!method_exists('CommonGLPI', 'can')) {
    if (!class_exists('CommonGLPI')) {
        class CommonGLPI {}
    }
    class CommonGLPIStub extends CommonGLPI {
        public function can($id, $right) { return true; }
    }
}
if (!method_exists('Migration', 'displayMessage')) {
    if (!class_exists('Migration')) {
        class Migration {}
    }
    class MigrationStub extends Migration {
        public function displayMessage($msg) { echo $msg; }
    }
}
if (!method_exists('DB', 'doQuery')) {
    if (!class_exists('DB')) {
        class DB {}
    }
    class DBStub extends DB {
        public function doQuery($query) { return true; }
    }
}
// --- End stubs ---
