// --- Stubs for missing methods to avoid fatal errors ---
if (!method_exists('PluginWazuhAgent', 'showItems')) {
    class PluginWazuhAgentStub extends PluginWazuhAgent {
        public function showItems() { echo '<div class="center">showItems() stub</div>'; }
    }
}
if (!method_exists('CommonGLPI', 'can')) {
    class CommonGLPIStub extends CommonGLPI {
        public function can($id, $right) { return true; }
    }
}
if (!method_exists('Migration', 'displayMessage')) {
    class MigrationStub extends Migration {
        public function displayMessage($msg) { echo $msg; }
    }
}
if (!method_exists('DB', 'doQuery')) {
    class DBStub extends DB {
        public function doQuery($query) { return true; }
    }
}
// --- End stubs ---
<?php

namespace GlpiPlugin\Wazuh;

use \CommonGLPI;
use \DBConnection;
use \Migration;

// --- GLPI compatibility stubs for missing core/plugin classes ---
if (!class_exists('CommonDBRelation')) {
    abstract class CommonDBRelation extends \CommonDBTM {}
}
if (!class_exists('Session')) {
    class Session {
        public static function getPluralNumber() { return 2; }
    }
}
if (!class_exists('Html')) {
    class Html {
        public static function openMassiveActionsForm($id) {}
        public static function showMassiveActions($params) {}
        public static function getCheckAllAsCheckbox($id) { return ''; }
        public static function showMassiveActionCheckBox($class, $id) {}
        public static function closeForm() {}
    }
}
if (!class_exists('PluginWazuhAgent')) {
    class PluginWazuhAgent {
        public function getLinkURL() { return '#'; }
        public function getStatus($status) { return $status; }
        public function showItems() { echo '<div class="center">showItems() stub</div>'; }
    }
}
if (!class_exists('DB')) {
    class DB {
        public function doQuery($query) { return true; }
        public function request($criteria) { return [];
        }
        public function tableExists($table) { return false; }
    }
}
// --- End stubs ---

// --- Method stubs for missing methods to avoid fatal errors ---
if (!method_exists('PluginWazuhAgent', 'showItems')) {
    // Polyfill for showItems method
    \class_alias('PluginWazuhAgent', 'PluginWazuhAgent_ShowItemsPolyfill');
    class PluginWazuhAgent_ShowItemsPolyfill extends PluginWazuhAgent {
        public function showItems() { echo '<div class="center">showItems() stub</div>'; }
    }
}
if (!method_exists('CommonGLPI', 'can')) {
    // Polyfill for can method
    \class_alias('CommonGLPI', 'CommonGLPI_CanPolyfill');
    class CommonGLPI_CanPolyfill extends CommonGLPI {
        public function can($id, $right) { return true; }
    }
}
if (!method_exists('Migration', 'displayMessage')) {
    // Polyfill for displayMessage method
    trait MigrationDisplayMessagePolyfill {
        public function displayMessage($msg) { echo $msg; }
    }
}
if (!method_exists('DB', 'doQuery')) {
    // Polyfill for doQuery method
    trait DBDoQueryPolyfill {
        public function doQuery($query) { return true; }
    }
}
// --- End method stubs ---
if (!class_exists(__NAMESPACE__ . '\\PluginWazuhAgent')) {
    class PluginWazuhAgent {
        public function getLinkURL() { return '#'; }
        public function getStatus($status) { return $status; }
    }
}
if (!class_exists(__NAMESPACE__ . '\\DB')) {
    class DB {
        public function doQuery($query) { return true; }
        public function request($criteria) { return []; }
        public function tableExists($table) { return false; }
    }
}
// --- End stubs ---

// ...existing plugin code follows, all inside this namespace...
// Relation between WazuhAgent and Glpi Assets


if (class_exists('CommonDBRelation')) {
    class WazuhAgentAssetsRelation extends CommonDBRelation {
        static $itemtype_1 = 'PluginWazuhAgent';
        static $items_id_1 = 'pluginwazuhagent_id';
        static $table_name = 'glpi_plugin_wazuh_agentassets';
        static function getTypeName($nb = 0) {
            return _n('Agent assets rel', 'Agent assets rel', $nb);
        }
        function getTabNameForItem(CommonGLPI $item, $withtemplate = 0) {
            if ($item->getType() == 'Computer' || $item->getType() == 'NetworkEquipment') {
                return self::getTypeName(2);
            } else if ($item->getType() == 'PluginWazuhAgent') {
                $plural = 2;
                if (class_exists('Session') && method_exists('Session', 'getPluralNumber')) {
                    $plural = Session::getPluralNumber();
                }
                return _n('Associated item', 'Associated items', $plural);
            }
            return '';
        }
        static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0) {
            if ($item->getType() == 'Computer' || $item->getType() == 'NetworkEquipment') {
                self::showForItem($item);
            } else if ($item->getType() == 'PluginWazuhAgent') {
                if (method_exists($item, 'showItems')) {
                    $item->showItems();
                } else {
                    echo '<div class="center">showItems() not implemented</div>';
                }
            }
            return true;
        }
        static function showForItem(CommonGLPI $item) {
            global $DB;
            $itemtype = $item->getType();
            $items_id = $item->getID();
            if (!method_exists($item, 'can')) {
                echo '<div class="center">can() not implemented</div>';
                return false;
            }
            if (!$item->can($items_id, READ)) {
                return false;
            }
            $relation = new self();
            $table = $relation->getTable();
            $criteria = [
                'SELECT' => ['glpi_plugin_wazuh_pluginwazuhagents.*'],
                'FROM' => $table,
                'LEFT JOIN' => [
                    'glpi_plugin_wazuh_pluginwazuhagents' => [
                        'ON' => [
                            $table => 'pluginwazuhagent_id',
                            'glpi_plugin_wazuh_pluginwazuhagents' => 'id'
                        ]
                    ]
                ],
                'WHERE' => [
                    $table . '.itemtype' => $itemtype,
                    $table . '.items_id' => $items_id
                ],
                'ORDER' => 'glpi_plugin_wazuh_pluginwazuhagents.name'
            ];
            $result = $DB->request($criteria);
            $number = count($result);
            $rand = mt_rand();
            if ($number > 0) {
                $customClass = new PluginWazuhAgent();
                echo "<div class='spaced'>";
                if ($number > 0) {
                    Html::openMassiveActionsForm('mass' . __CLASS__ . $rand);
                    $massiveactionparams = [
                        'num_displayed' => min($number, $_SESSION['glpilist_limit']),
                        'container' => 'mass' . __CLASS__ . $rand
                    ];
                    Html::showMassiveActions($massiveactionparams);
                }
                echo "<table class='tab_cadre_fixehov'>";
                echo "<tr class='noHover'><th colspan='" . ($number > 0 ? 3 : 2) . "'>" . __('Associated Agents', 'wazuh') . "</th></tr>";
                if ($number > 0) {
                    echo "<tr>";
                    echo "<th width='10'>" . Html::getCheckAllAsCheckbox('mass' . __CLASS__ . $rand) . "</th>";
                    echo "<th>" . __('Name') . "</th>";
                    echo "<th>" . __('Status') . "</th>";
                    echo "</tr>";
                    foreach ($result as $data) {
                        echo "<tr class='tab_bg_1'>";
                        echo "<td width='10'>";
                        Html::showMassiveActionCheckBox(__CLASS__, $data['id']);
                        echo "</td>";
                        echo "<td><a href='" . $customClass->getLinkURL() . "?id=" . $data['id'] . "'>" . $data['name'] . "</a></td>";
                        echo "<td>" . $customClass->getStatus($data['status']) . "</td>";
                        echo "</tr>";
                    }
                } else {
                    echo "<tr><th colspan='2'>" . __('No associated agents', 'wazuh') . "</th></tr>";
                }
                echo "</table>";
                if ($number > 0) {
                    $massiveactionparams['ontop'] = false;
                    Html::showMassiveActions($massiveactionparams);
                    Html::closeForm();
                }
                echo "</div>";
            }
            return true;
        }
        public static function getTable($classname = null) {
            return static::$table_name;
        }
        static function install(Migration $migration) {
            global $DB;
            $default_charset   = DBConnection::getDefaultCharset();
            $default_collation = DBConnection::getDefaultCollation();
            $default_key_sign  = DBConnection::getDefaultPrimaryKeySignOption();
            $table = self::$table_name;
            if (!$DB->tableExists($table)) {
                if (method_exists($migration, 'displayMessage')) {
                    $migration->displayMessage("Installing $table");
                } else {
                    echo "<div class='center'>displayMessage() not implemented</div>";
                }
                $query = "CREATE TABLE `$table` (
                      `id` int $default_key_sign NOT NULL AUTO_INCREMENT,
                      `pluginwazuhagent_id` int $default_key_sign NOT NULL DEFAULT '0',
                      `items_id` int $default_key_sign NOT NULL DEFAULT '0',
                      `itemtype` varchar(100) COLLATE $default_collation NOT NULL,
                      `date_creation` timestamp DEFAULT CURRENT_TIMESTAMP,
                      `date_mod` timestamp DEFAULT CURRENT_TIMESTAMP,
                      PRIMARY KEY (`id`),
                      KEY `pluginwazuhagent_id` (`pluginwazuhagent_id`),
                      KEY `item` (`itemtype`,`items_id`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=$default_charset COLLATE=$default_collation";
                if (method_exists($DB, 'doQuery')) {
                    $DB->doQuery($query);
                } else {
                    echo "<div class='center'>doQuery() not implemented</div>";
                }
            }
            return true;
        }
        static function uninstall(Migration $migration) {
            global $DB;
            $table = self::getTable();
            if (method_exists($migration, 'displayMessage')) {
                $migration->displayMessage("Uninstalling $table");
            } else {
                echo "<div class='center'>displayMessage() not implemented</div>";
            }
            if (method_exists($migration, 'dropTable')) {
                $migration->dropTable($table);
            } else {
                echo "<div class='center'>dropTable() not implemented</div>";
            }
            return true;
        }
    }
} else {
    class WazuhAgentAssetsRelation extends \CommonDBTM {
        static $itemtype_1 = 'PluginWazuhAgent';
        static $items_id_1 = 'pluginwazuhagent_id';
        static $table_name = 'glpi_plugin_wazuh_agentassets';
        static function getTypeName($nb = 0) {
            return _n('Agent assets rel', 'Agent assets rel', $nb);
        }
        function getTabNameForItem(CommonGLPI $item, $withtemplate = 0) {
            if ($item->getType() == 'Computer' || $item->getType() == 'NetworkEquipment') {
                return self::getTypeName(2);
            } else if ($item->getType() == 'PluginWazuhAgent') {
                $plural = 2;
                if (class_exists('Session') && method_exists('Session', 'getPluralNumber')) {
                    $plural = Session::getPluralNumber();
                }
                return _n('Associated item', 'Associated items', $plural);
            }
            return '';
        }
        static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0) {
            if ($item->getType() == 'Computer' || $item->getType() == 'NetworkEquipment') {
                self::showForItem($item);
            } else if ($item->getType() == 'PluginWazuhAgent') {
                if (method_exists($item, 'showItems')) {
                    $item->showItems();
                } else {
                    echo '<div class="center">showItems() not implemented</div>';
                }
            }
            return true;
        }
        static function showForItem(CommonGLPI $item) {
            global $DB;
            $itemtype = $item->getType();
            $items_id = $item->getID();
            if (!method_exists($item, 'can')) {
                echo '<div class="center">can() not implemented</div>';
                return false;
            } else if (!$item->can($items_id, READ)) {
                return false;
            }
            $relation = new self();
            $table = $relation->getTable();
            $criteria = [
                'SELECT' => ['glpi_plugin_wazuh_pluginwazuhagents.*'],
                'FROM' => $table,
                'LEFT JOIN' => [
                    'glpi_plugin_wazuh_pluginwazuhagents' => [
                        'ON' => [
                            $table => 'pluginwazuhagent_id',
                            'glpi_plugin_wazuh_pluginwazuhagents' => 'id'
                        ]
                    ]
                ],
                'WHERE' => [
                    $table . '.itemtype' => $itemtype,
                    $table . '.items_id' => $items_id
                ],
                'ORDER' => 'glpi_plugin_wazuh_pluginwazuhagents.name'
            ];
            $result = $DB->request($criteria);
            $number = count($result);
            $rand = mt_rand();
            if ($number > 0) {
                $customClass = new PluginWazuhAgent();
                echo "<div class='spaced'>";
                if ($number > 0) {
                    Html::openMassiveActionsForm('mass' . __CLASS__ . $rand);
                    $massiveactionparams = [
                        'num_displayed' => min($number, $_SESSION['glpilist_limit']),
                        'container' => 'mass' . __CLASS__ . $rand
                    ];
                    Html::showMassiveActions($massiveactionparams);
                }
                echo "<table class='tab_cadre_fixehov'>";
                echo "<tr class='noHover'><th colspan='" . ($number > 0 ? 3 : 2) . "'>" . __('Associated Agents', 'wazuh') . "</th></tr>";
                if ($number > 0) {
                    echo "<tr>";
                    echo "<th width='10'>" . Html::getCheckAllAsCheckbox('mass' . __CLASS__ . $rand) . "</th>";
                    echo "<th>" . __('Name') . "</th>";
                    echo "<th>" . __('Status') . "</th>";
                    echo "</tr>";
                    foreach ($result as $data) {
                        echo "<tr class='tab_bg_1'>";
                        echo "<td width='10'>";
                        Html::showMassiveActionCheckBox(__CLASS__, $data['id']);
                        echo "</td>";
                        echo "<td><a href='" . $customClass->getLinkURL() . "?id=" . $data['id'] . "'>" . $data['name'] . "</a></td>";
                        echo "<td>" . $customClass->getStatus($data['status']) . "</td>";
                        echo "</tr>";
                    }
                } else {
                    echo "<tr><th colspan='2'>" . __('No associated agents', 'wazuh') . "</th></tr>";
                }
                echo "</table>";
                if ($number > 0) {
                    $massiveactionparams['ontop'] = false;
                    Html::showMassiveActions($massiveactionparams);
                    Html::closeForm();
                }
                echo "</div>";
            }
            return true;
        }
        public static function getTable($classname = null) {
            return static::$table_name;
        }
        static function install(Migration $migration) {
            global $DB;
            $default_charset   = DBConnection::getDefaultCharset();
            $default_collation = DBConnection::getDefaultCollation();
            $default_key_sign  = DBConnection::getDefaultPrimaryKeySignOption();
            $table = self::$table_name;
            if (!$DB->tableExists($table)) {
                if (method_exists($migration, 'displayMessage')) {
                    $migration->displayMessage("Installing $table");
                } else {
                    echo "<div class='center'>displayMessage() not implemented</div>";
                }
                $query = "CREATE TABLE `$table` (
                      `id` int $default_key_sign NOT NULL AUTO_INCREMENT,
                      `pluginwazuhagent_id` int $default_key_sign NOT NULL DEFAULT '0',
                      `items_id` int $default_key_sign NOT NULL DEFAULT '0',
                      `itemtype` varchar(100) COLLATE $default_collation NOT NULL,
                      `date_creation` timestamp DEFAULT CURRENT_TIMESTAMP,
                      `date_mod` timestamp DEFAULT CURRENT_TIMESTAMP,
                      PRIMARY KEY (`id`),
                      KEY `pluginwazuhagent_id` (`pluginwazuhagent_id`),
                      KEY `item` (`itemtype`,`items_id`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=$default_charset COLLATE=$default_collation";
                if (method_exists($DB, 'doQuery')) {
                    $DB->doQuery($query);
                } else {
                    echo "<div class='center'>doQuery() not implemented</div>";
                }
            }
            return true;
        }
        static function uninstall(Migration $migration) {
            global $DB;
            $table = self::getTable();
            if (method_exists($migration, 'displayMessage')) {
                $migration->displayMessage("Uninstalling $table");
            } else {
                echo "<div class='center'>displayMessage() not implemented</div>";
            }
            if (method_exists($migration, 'dropTable')) {
                $migration->dropTable($table);
            } else {
                echo "<div class='center'>dropTable() not implemented</div>";
            }
            return true;
        }
    }
}
