#!/usr/bin/python3
#
# Script to manage B2-stored backups
#
# Copyright (c) 2009-2013 Ryan S. Tucker
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from argparse import ArgumentParser
from collections import defaultdict
from datetime import datetime, timedelta
from os import environ, getuid
from pathlib import Path
from pwd import getpwuid
from subprocess import Popen
from sys import argv

from b2sdk.v2 import FileVersion
from b2sdk.v2 import InMemoryAccountInfo, B2Api, Bucket
from math import log10
from progress.bar import ChargingBar

import secrets


class BackupManager:
    def __init__(self, access_key: str, shared_key: str):
        self._access_key = access_key
        b2_info = InMemoryAccountInfo()
        self._connection = B2Api(b2_info)
        self._connection.authorize_account("production", self._access_key, shared_key)

        self._buckets = None
        self._bucket_backups = {}
        self._backups = None

    def _generate_backup_buckets(self) -> [Bucket]:
        bucket_prefix = f"{self._access_key}-bckpc-".lower()
        buckets = self._connection.list_buckets()
        self._buckets = []

        for bucket in buckets:
            if bucket.name.startswith(bucket_prefix):
                self._buckets.append(bucket)

    @property
    def backup_buckets(self) -> [Bucket]:
        if self._buckets is None:
            self._generate_backup_buckets()
        return self._buckets

    @staticmethod
    def _list_backups(bucket: Bucket) -> {}:
        """
        Returns a dict of backups in a bucket, with dicts of:
        {hostname (str):
            {Backup number (int):
                {
                 "date": Datetime of backup (int),
                 "files": A list of files comprising the backup,
                 "hostname": Hostname (str),
                 "backup_num": Backup number (int),
                 "finalized": 0, or the timestamp the backup was finalized,
                 "bucket": the bucket of the backup
                }
            }
        }
        """

        backups = {}

        for file in filter(lambda e: isinstance(e, FileVersion), map(lambda e: e[0], bucket.ls())):
            file: FileVersion = file
            parts = file.file_name.split(".")
            final = False

            if parts[-1] == "COMPLETE":
                final = True
                parts.pop()  # back to tar
                parts.pop()  # back to backup number
            else:
                if parts[-1] == "gpg":
                    parts.pop()

                if parts[-1] != "tar" and len(parts[-1]) == 2:
                    parts.pop()

                if parts[-1] == "tar":
                    parts.pop()

            nextpart = parts.pop()
            if nextpart == "COMPLETE":
                print(f"Stray file: {file.file_name}")
                continue
            backup_num = int(nextpart)
            hostname = ".".join(parts)

            upload_timestamp = file.upload_timestamp//1000
            lastmod = datetime.utcfromtimestamp(upload_timestamp)

            if hostname in backups.keys():
                if backup_num not in backups[hostname].keys():
                    backups[hostname][backup_num] = {
                        "date": lastmod,
                        "hostname": hostname,
                        "backup_num": backup_num,
                        "finalized": 0,
                        "files": [],
                        "final_file": None,
                        "finalized_age": -1,
                        "bucket": bucket
                    }
            else:
                backups[hostname] = {
                    backup_num: {
                        "date": lastmod,
                        "hostname": hostname,
                        "backup_num": backup_num,
                        "finalized": 0,
                        "files": [],
                        "final_file": None,
                        "finalized_age": -1,
                        "bucket": bucket
                    }
                }
            if final:
                backups[hostname][backup_num]["finalized"] = upload_timestamp
                backups[hostname][backup_num]["final_file"] = file

                delta = int((lastmod - datetime.now()).total_seconds() * 1000000)
                backups[hostname][backup_num]["finalized_age"] = delta
            else:
                if lastmod < backups[hostname][backup_num]["date"]:
                    backups[hostname][backup_num]["date"] = lastmod
                backups[hostname][backup_num]["files"].append(file)
        return backups

    def get_backups_by_bucket(self, bucket: Bucket) -> {}:
        if bucket.name not in self._bucket_backups:
            self._bucket_backups[bucket.name] = self._list_backups(bucket)

        return self._bucket_backups[bucket.name]

    @property
    def all_backups(self) -> [{}]:
        if self._backups is None:
            self._backups = {}
            for bucket in self.backup_buckets:
                backups_dict = self.get_backups_by_bucket(bucket)
                for hostname, backups in backups_dict.items():
                    if hostname not in self._backups:
                        self._backups[hostname] = {}
                    self._backups[hostname].update(backups)
        return self._backups

    def invalidate_host_cache(self, hostname):
        nuke = []
        for bucket in self._bucket_backups:
            if hostname in self._bucket_backups[bucket]:
                nuke.append(bucket)

        for bucket in nuke:
            if bucket in self._bucket_backups:
                del self._bucket_backups[bucket]
                self._backups = None

    @property
    def backups_by_age(self):
        """
        Returns a dict of {hostname: [(backup_num, age), ...]}
        """
        results = defaultdict(list)
        for hostname, backups in self.all_backups.items():
            for backup_num, statusdict in backups.items():
                results[hostname].append((backup_num,
                                          statusdict["finalized_age"]))
        return results


def choose_host_to_backup(age_dict, target_count=2):
    """
    Takes a dict from backups_by_age, returns a hostname to back up.
    """

    host_scores = defaultdict(int)

    for hostname, backup_list in age_dict.items():
        bl = sorted(backup_list, key=lambda x: x[1])
        if len(bl) > 0 and bl[0][1] == -1:
            # unfinalized backup alert
            host_scores[hostname] += 200
            bl.pop(0)
        if len(bl) >= target_count:
            host_scores[hostname] -= 100
        host_scores[hostname] -= len(bl)
        if len(bl) > 0:
            # age of the oldest backup helps score
            oldest = bl[0]
            host_scores[hostname] += log10(oldest[1])
            # recency of the newest backup hurts score
            newest = bl[-1]
            host_scores[hostname] -= log10(max(1, (oldest[1] - newest[1])))

    for candidate, score in sorted(host_scores.items(),
                                   key=lambda x: x[1], reverse=True):
        yield candidate, score


def choose_backups_to_delete(agedict, target_count=2, max_age=30):
    """
    Takes a dict from backups_by_age, returns a list of backups to delete
    """

    decimate = defaultdict(list)

    for hostname, backuplist in agedict.items():
        bl = []
        for backup in sorted(backuplist, key=lambda x: x[1]):
            if backup[1] > 0:
                bl.append(backup)

        while len(bl) > target_count:
            backup = bl.pop()
            if backup[1] > (max_age * 24 * 60 * 60):
                decimate[hostname].append(backup)

    return decimate


def make_restore_script(backup: {}, expire=86400) -> str:
    """
    Returns a quick and easy restoration script to restore the given system,
    requires a backup, and perhaps expire
    """

    hostname = backup["hostname"]
    backup_num = backup["backup_num"]
    bucket = backup["bucket"]
    friendly_time = backup["date"].strftime("%Y-%m-%d at %H:%M GMT")

    expire_time = datetime.now() + timedelta(seconds=expire)

    files = [f"'{bucket.get_download_url(i.file_name)}'" for i in backup["files"] + [backup["final_file"]]]

    output = f"""#!/bin/bash
# Restoration script for {hostname} backup {backup_num},
# a backup created on {friendly_time}.
# To use: bash scriptname /path/to/put/the/files

# WARNING: THIS FILE EXPIRES AFTER {expire_time.strftime("%Y-%m-%d at %H:%M GMT")}
if (( "$(date +%s)" > "{int(expire_time.timestamp() * 1000000)}" )); then
    echo "Sorry, this restore script is too old."
    exit 1
elif [ -z "$1" ]; then
    echo "Usage: ./scriptname /path/to/restore/to"
    exit 1
elif [ ! -d "$1" ]; then
    echo "Target $1 does not exist!"
    exit 1
elif [ -n "$(ls --almost-all "$1")" ]; then
    echo "Target $1 is not empty!"
    exit 1
fi

# cd to the destination, create a temporary workspace
cd "$1"
tmp_dir="$i/.restorescript-scratch"
mkdir "$tmp_dir"

files=({' '.join(files)})
token='{bucket.get_download_authorization(f'{hostname}.{backup_num}', expire)}'

declare –a out_files
for i in "${{files[@]}}"; do
    filename="$(echo "$i" | cut -d/ -f6)"
    curl "$i" -o "$tmp_dir/$filename" -H "Authorization: $token"
    if (( $? != 0 )); then
        echo "Error during download !"
        exit 1
    fi
    out_files+=("$tmp_dir/$filename")
done

# decrypt files
gpg --decrypt-files "${{out_files[@]}}"

# join and untar files
cat "$tmp_dir/*.tar.??" | tar -xf -

echo "DONE!  Have a nice day."
"""
    return output


def start_archive(hosts):
    """
    Starts an archive operation for a list of hosts.
    """
    if "LOGNAME" in environ:
        username = environ["LOGNAME"]
    else:
        try:
            username = getpwuid(getuid()).pw_name
        except KeyError:
            username = "nobody"

    cmd = [Path(argv[0]).parents[0] / "BackupPC_archiveStart", "archives3", username]
    cmd.extend(hosts)

    proc = Popen(cmd)
    proc.communicate()


def script(parser: ArgumentParser, bmgr: BackupManager, host: str, unfinalized: bool, backup_num: int = None,
           expire: int = 86400, filename: str = None):
    if not backup_num and unfinalized:
        # assuming highest number
        backup_num = max(bmgr.all_backups[host].keys())
    elif not backup_num:
        # assuming highest finalized number
        backup_num = 0
        for backup in bmgr.all_backups[host].keys():
            if bmgr.all_backups[host][backup]["finalized"] > 0:
                backup_num = max(backup_num, backup)
        if backup_num == 0:
            parser.error("No finalized backups found!  Try --unfinalized if you dare")

    backup = bmgr.all_backups[host][backup_num]

    if filename:
        with open(filename, "w") as fd:
            fd.write(make_restore_script(backup, expire=expire))
    else:
        print(make_restore_script(backup, expire=expire))


def delete(bm: BackupManager, keep: int, host: str, backup_num: int, age: int, test: bool,
           start: bool):
    to_delete = []
    if host and backup_num:
        print(f"Will delete backup: {host} {backup_num} (forced)")
        to_delete.append((host, backup_num))
    elif age:
        to_delete_dict = choose_backups_to_delete(bm.backups_by_age, target_count=keep, max_age=age)
        for hostname, backup_list in to_delete_dict.items():
            for backup_stat in backup_list:
                print(f"Will delete backup: {hostname} {backup_stat[0]} (expired at {backup_stat[1] / 86400.0} days)")
                to_delete.append((hostname, backup_stat[0]))
    else:
        return

    for delete_host, delete_backup_num in to_delete:
        host_backups = bm.all_backups.get(delete_host, {})
        delete_backup = host_backups.get(delete_backup_num, {})
        delete_files = delete_backup.get("files", [])
        final_file = delete_backup.get("final_file", None)
        if len(delete_files) > 0:
            for file in ChargingBar(f"Deleting backup {delete_host} #{delete_backup_num}:", max=len(delete_files)).\
                    iter(delete_files):
                if not test:
                    file.delete()

            if final_file and not test:
                final_file.delete()

    if start:
        for delete_host, delete_backup_num in to_delete:
            bm.invalidate_host_cache(delete_host)
        score_iter = choose_host_to_backup(bm.backups_by_age, target_count=int(keep) + 1)
        for candidate, score in score_iter:
            if score > 0:
                print(f"Starting archive operation for host: {candidate} (score={score})")
                start_archive([candidate])
                break


def list_backups(bm: BackupManager):
    print(f"{'Hostname':>25} | {'Bkup#':>5} | {'Age':>30} | {'Files':>5}")
    print(("-" * 72))
    
    for hostname, backups in bm.all_backups.items():
        for backup_num in sorted(backups.keys()):
            filecount = len(backups[backup_num]["files"])
            date = backups[backup_num]["date"]
            if backups[backup_num]["finalized"] > 0:
                in_progress = ""
            else:
                in_progress = "*"

            print(f"{hostname:>25} | {backup_num:>5} | {str(datetime.now() - date):>30} | {filecount:>5}{in_progress}")
    print("* = not yet finalized (Age = time of last activity)")


def main():
    parser = ArgumentParser(description="Companion maintenance script for BackupPC_archiveHost_s3. " +
                                        "By default, it assumes the 'list' command, which displays all " +
                                        "of the backups currently archived on B2.  The 'delete' command " +
                                        "is used to delete backups.  The 'script' command produces a " +
                                        "script that can be used to download and restore a backup.")
    parser.add_argument("-l", "--list", dest="list", action="store_true",
                        help="List stored backups after completing operations")

    subparsers = parser.add_subparsers(required=True, dest="action")
    subparsers.add_parser("list")

    delete_parser = subparsers.add_parser("delete")
    delete_parser.add_argument("-s", "--start-backups", dest="start", action="store_true",
                               help="When used with --age, start backups for hosts with fewer than keep+1 backups")
    delete_parser.add_argument("-k", "--keep", dest="keep", help="When used with --age, keep this many recent backups",
                               default=1)
    delete_parser.add_argument("-t", "--test", dest="test", action="store_true",
                               help="Test mode; don't actually delete")
    delete_parser.add_argument("-H", "--host", dest="host", help="Name of backed-up host")
    delete_parser.add_argument("-b", "--backup-number", dest="backup_num", type=int, help="Backup number")
    delete_parser.add_argument("-a", "--age", dest="age", help="Delete backups older than AGE days")

    script_parser = subparsers.add_parser("script")
    script_parser.add_argument("-H", "--host", dest="host", required=True, help="Name of backed-up host")
    script_parser.add_argument("-b", "--backup-number", dest="backup_num", type=int, help="Backup number")
    script_parser.add_argument("-f", "--filename", dest="filename", help="Output filename for script")
    script_parser.add_argument("-x", "--expire", dest="expire", default=86400, help="Maximum age of script")
    script_parser.add_argument("-u", "--unfinalized", dest="unfinalized", action="store_true",
                               help="Consider unfinalized backups")

    args = parser.parse_args()

    bm = BackupManager(secrets.access_key, secrets.shared_key)

    if args.action == "script" or args.action == "delete":
        if args.backup_num and not args.host:
            parser.error("Must specify --host when specifying --backup-number")

        if args.host:
            if args.host not in bm.all_backups:
                parser.error(f"No backups found for host \"{args.host}\"")
        else:
            if len(bm.all_backups) == 0:
                parser.error("No buckets found!")

    if args.action == "script":
        script(parser, bm, args.host, args.backup_num, args.unfinalized, args.expire, args.filename)
    elif args.action == "delete":
        if not (args.age or args.host or args.backup_num):
            parser.error("--age or --host and --backup-number are required")
        elif args.host and not args.backup_num:
            parser.error("--backup-number required with --host")
        elif args.age and (args.host or args.backup_num):
            parser.error("--age can't be combined with --host or --backup-number")
        elif args.start and not args.age:
            parser.error("--start-backups only makes sense with --age")

        delete(bm, args.keep, args.host, args.backup_num, args.age, args.test, args.start)

    if args.action == "list" or args.list:
        list_backups(bm)


if __name__ == "__main__":
    main()
