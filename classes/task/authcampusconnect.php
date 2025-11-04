<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Scheduled task that removes relicts and unnecessary artifacts from the DB.
 *
 * @package auth_campusconnect
 * @copyright 2023 Wunderbyte GmbH <info@wunderbyte.at>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace auth_campusconnect\task;

use auth_plugin_campusconnect;
use local_campusconnect\ecssettings;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot . '/local/campusconnect/lib.php');

/**
 * Class to handle scheduled task that removes relicts and unnecessary artifacts from the DB.
 *
 * @package auth_campusconnect
 * @copyright 2024 Wunderbyte GmbH <info@wunderbyte.at>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class authcampusconnect extends \core\task\scheduled_task {
    /**
     * Get name of module.
     * @return string
     * @throws \coding_exception
     */
    public function get_name() {
        return get_string('campusconnecttask', 'auth_campusconnect');
    }

    /**
     * Scheduled task syncs with ECS server.
     * @throws \coding_exception
     * @throws \dml_exception
     * @throws \moodle_exception
     */
    public function execute() {
        global $CFG, $DB;

        // Cron - delete users who timed out and never enrolled.
        // Inactivate users who haven't been active for some time.
        // And notify relevant users about users created.

        // Find users whose session should have expired by now and haven't ever enroled in a course.
        $params = [
            'minaccess' => time() - $CFG->sessiontimeout,
        ];
        $sql = "
        SELECT u.id, u.username
          FROM {user} u
          JOIN {auth_campusconnect} ac ON ac.username = u.username
         WHERE u.deleted = 0 AND u.lastaccess < :minaccess
           AND ac.lastenroled IS NULL
        ";
        $deleteusers = $DB->get_records_sql($sql, $params);
        foreach ($deleteusers as $deleteuser) {
            mtrace(get_string('deletinguser', 'auth_campusconnect') . ': ' . $deleteuser->id);
            auth_plugin_campusconnect::user_dataprotect_delete($deleteuser);
        }

        // Make users who haven't enrolled in a long time inactive.
        $ecslist = ecssettings::list_ecs();
        $ecsemails = []; // We'll need it for later.
        foreach ($ecslist as $ecsid => $ecsname) {
            // Get the activation period.
            $settings = new ecssettings($ecsid);
            $monthsago = $settings->get_import_period();
            $month = date('n') - $monthsago;
            $year = date('Y');
            $day = date('j');
            if ($month < 1) {
                $year += floor(($month - 1) / 12);
                $month = $month % 12 + 12;
            }
            $cutoff = mktime(date('H'), date('i'), date('s'), $month, $day, $year);
            $sql = "SELECT u.id, ac.pids
                      FROM {user} u
                      JOIN {auth_campusconnect} ac ON u.username = ac.username
                     WHERE u.suspended = 0 AND u.deleted = 0 AND ac.lastenroled IS NOT NULL AND ac.lastenroled < :cutoff
                   ";
            $params = ['cutoff' => $cutoff];
            $users = $DB->get_records_sql($sql, $params);
            $userids = [];
            foreach ($users as $user) {
                if (auth_plugin_campusconnect::matches_ecsid($user->pids, $ecsid)) {
                    $userids[] = $user->id;
                }
            }
            if (!empty($userids)) {
                [$usql, $params] = $DB->get_in_or_equal($userids);
                $DB->execute("UPDATE {user}
                                 SET suspended = 1
                               WHERE id $usql", $params);
                // Trigger an event for all users.
                foreach ($DB->get_recordset_list('user', 'id', $userids) as $user) {
                    // Just in case the user is currently logged in.
                    if (method_exists('\core\session\manager', 'destroy_user_sessions')) {
                        \core\session\manager::destroy_user_sessions($user->id);
                    } else {
                        // Keep this for backwards compatibility.
                        \core\session\manager::kill_user_sessions($user->id);
                    }
                    \core\event\user_updated::create_from_userid($user->id)->trigger();
                }
            }

            // For later.
            $ecsemails[$ecsid] = $settings->get_notify_users();
        }

        // Notify relevant users about new accounts.
        if (!$lastsent = get_config('auth_campusconnect', 'lastnewusersemailsent')) {
            $lastsent = 0;
        }
        $sendupto = time() - 1;
        $params = [
            'auth' => 'campusconnect',
            'lastsent' => $lastsent,
            'sendupto' => $sendupto,
        ];
        $sql = "
        SELECT u.*, ac.pids
          FROM {user} u
          JOIN {auth_campusconnect} ac ON ac.username = u.username
         WHERE deleted = 0
           AND u.timecreated > :lastsent
           AND u.timecreated <= :sendupto
        ";
        $newusers = $DB->get_records_sql($sql, $params);
        $adminuser = get_admin();
        $notified = [];
        foreach ($newusers as $newuser) {
            $subject = get_string('newusernotifysubject', 'auth_campusconnect');
            $messagetext = get_string('newusernotifybody', 'auth_campusconnect', $newuser);
            $ecsids = auth_plugin_campusconnect::get_ecsids($newuser->pids);
            foreach ($ecsids as $ecsid) {
                if (!isset($ecslist[$ecsid])) {
                    mtrace(get_string('usernamecantfindecs', 'auth_campusconnect') . ': ' . $newuser->username);
                    continue;
                }
                if (!isset($notified[$ecsid])) {
                    [$in, $params] = $DB->get_in_or_equal($ecsemails[$ecsid]);
                    $notified[$ecsid] = $DB->get_records_select('user', "username $in", $params);
                }
                foreach ($notified[$ecsid] as $recepient) {
                    email_to_user($recepient, $adminuser, $subject, $messagetext);
                }
            }
        }

        set_config('lastnewusersemailsent', $sendupto, 'auth_campusconnect');

        return true;
    }
}
