#!/usr/bin/python3
# A BackupPC script to archive a host"s files to Backblaze B2.
#
# Point $Conf{ArchiveClientCmd} at me.
# see requirements.txt
#
# Usage: BackupPC_archiveHost_b2.py tarCreatePath splitPath parPath host bkupNum \
#             compPath fileExt splitSize outLoc parFile share
#
# Create secrets.py such that it has:
# access_key = "amazon aws access key"
# shared_key = "amazon aws shared key"
# gpg_symmetric_key = "gpg symmetric key -- make it good, but do not lose it"
#
# Copyright (c) 2009-2011 Ryan S. Tucker
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
from hashlib import md5, sha1
from logging import getLogger, Formatter, StreamHandler, DEBUG, WARNING, INFO
from logging.handlers import RotatingFileHandler
from multiprocessing import Process, Queue, cpu_count
from os import access, X_OK, nice
from pathlib import Path
from re import search, escape
from subprocess import Popen
from sys import stdout
from time import time, sleep
from typing import Dict

from b2sdk.v2 import InMemoryAccountInfo, B2Api, Bucket, AbstractProgressListener
from b2sdk.v2.exception import B2Error, NonExistentBucket
from gnupg import GPG
from math import ceil
from progress.bar import ChargingBar

import secrets


logger = getLogger(__name__)
logger_formatter = Formatter("%(asctime)s: %(levelname)s: %(message)s")
file_handler = RotatingFileHandler("/tmp/archive_run.log")
file_handler.setFormatter(logger_formatter)
logger.addHandler(file_handler)
console_handler = StreamHandler(stdout)
console_handler.setFormatter(logger_formatter)
logger.addHandler(console_handler)
logger.setLevel(INFO)

b2_info = InMemoryAccountInfo()
b2_api = B2Api(b2_info)

Path("/tmp/gnupg").mkdir(parents=True, exist_ok=True)
gpg = GPG(gpgbinary="/usr/bin/gpg2", gnupghome="/tmp/gnupg")


class ProgressListener(AbstractProgressListener):
    """
    Listener for B2 progression printed in logger every percent
    """
    total_byte_count = 0
    total_send_bytes = 0
    bar = None
    enable = True

    def __init__(self, filename: str):
        """
        :param filename: The name of the file targeted for the progression
        """
        super().__init__()
        self.filename = filename
        self.bar = ChargingBar(filename)

    def set_total_bytes(self, total_byte_count: int):
        """
        Set the total byte count
        :param total_byte_count: The total count of bytes
        """
        self.total_byte_count = total_byte_count
        self.bar.max = self.total_byte_count
        self.enable = True

    def bytes_completed(self, byte_count: int):
        """
        Indicate the progression
        :param byte_count: The number of bytes made during the last action
        """
        if not self.enable:
            return

        self.total_send_bytes += byte_count
        self.bar.next(byte_count)
        if self.total_send_bytes >= self.total_byte_count:
            self.bar.finish()
            self.enable = False


def sizeof_fmt(num: int, suffix="B") -> str:
    """
    Reformat size to human-readable string
    :param num: The size
    :param suffix: The input size unit
    :return: The size in a human-readable version
    """
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def exec_path(path: str) -> Path:
    """
    Check if the given string is a valid path and an executable
    :param path: The executable path
    :return: The path object if valid
    :raise ValueError: If the path didn't exist or is not an executable
    """
    path = Path(path)
    if not path.exists() or not is_exe(path):
        raise ValueError("Path not executable")
    else:
        return path


def dir_path(path: str) -> Path:
    """
    Check if the given string is a valid path and a directory
    :param path: The directory path
    :return: The path object if valid
    :raise ValueError: If the path didn't exist or is not a directory
    """
    path = Path(path)
    if not path.exists() or not path.is_dir():
        raise ValueError("Path not a directory")
    else:
        return path


def positive_int(i: str) -> int:
    i = int(i)
    if i <= 0:
        raise ValueError("Should be greater than 0")
    return i


def is_exe(fpath: Path) -> bool:
    """
    Check if a file est executable
    :param fpath: The path to the file to check
    :return: True if the file is executable, False instead
    """
    return fpath.exists() and access(fpath, X_OK)


def encrypt_file(filename: Path, key: str, compress: Path = Path("/bin/cat")) -> Path:
    """
    Encrypt a file with a kay and compress it, returning the path to the new file
    :param filename: The path to the file to encrypt
    :param key: The key for encryption
    :param compress: The compression used
    :return: The path to the encrypted file
    """
    compress_map = {"cat": "none", "gzip": "ZLIB", "bzip2": "BZIP2"}
    encrypt_output = Path(f"{filename}.gpg")

    if compress.name in compress_map.keys():
        compress_algo = compress_map[compress.name]
    else:
        compress_algo = "none"

    logger.debug(f"encrypt_file: encrypting {filename} (compression: {compress_algo})")
    with open(filename, "rb") as f:
        gpg.encrypt_file(file=f, output=encrypt_output, recipients=None, symmetric=True, passphrase=key,
                         armor=False, extra_args=["--compress-algo", compress_algo])

    if encrypt_output.exists() and encrypt_output.stat().st_size:
        old_filesize = filename.stat().st_size
        new_filesize = encrypt_output.stat().st_size

        compressed = ((old_filesize - new_filesize) / float(old_filesize)) * 100
        logger.debug(f"encrypt_file: {filename} {'shrunk' if old_filesize > new_filesize else 'grew'} by "
                     f"{compressed:.2f}% ({sizeof_fmt(old_filesize)} -> {sizeof_fmt(new_filesize)})")
        return encrypt_output
    else:
        raise RuntimeError(f"output file does not exist: {encrypt_output}")


def open_b2(access_key: str, shared_key: str, host: str) -> Bucket:
    """
    Get the B2 bucket for a host
    :param access_key: The application key id
    :param shared_key: The application key
    :param host: The host name to generate the bucket name
    :return: The host B2 bucket
    """
    b2_api.authorize_account("production", access_key, shared_key)
    my_bucket_name = f"{access_key}-bckpc-{host.replace('.', '-')}".lower()
    lifecycle_rules = [{
        'daysFromHidingToDeleting': 1,
        'daysFromUploadingToHiding': None,
        'fileNamePrefix': ''
    }]

    try:
        bucket = b2_api.get_bucket_by_name(my_bucket_name)
    except NonExistentBucket:
        logger.info(f"open_b2: creating new bucket {my_bucket_name}")
        # noinspection PyTypeChecker
        bucket = b2_api.create_bucket(my_bucket_name, "allPrivate", lifecycle_rules=lifecycle_rules)
    return bucket


def get_file_hash(file: Path, algo: str = "md5") -> str:
    """
    Get the hash of a file
    :param file: The path to the file
    :param algo: The hash algorithm (sha1/md5)
    :return: The hash string
    """
    if algo.lower() == "md5":
        file_hash = md5()
    elif algo.lower() == "sha1":
        file_hash = sha1()
    else:
        raise ValueError("Invalid algo")

    with open(file, "rb") as fp:
        while True:
            data = fp.read(65536)
            if not data:
                break
            file_hash.update(data)

    return file_hash.hexdigest()


def verify_file(bucket: Bucket, filename: Path, base_filename: str) -> bool:
    """
    Check if a local file is the same as a file in the bucket
    :param bucket: The target bucket
    :param filename: The path ot the file to check
    :param base_filename: The filename inside the bucket
    :return: True if the file size and hash match, False otherwise
    """
    file_stat = filename.stat()
    info = next(bucket.list_file_versions(base_filename), None)

    if not info or info.size != file_stat.st_size:
        return False
    elif info.content_md5 and info.content_md5 != "none":
        remote_hash = info.content_md5
        algo = "md5"
    elif info.content_sha1 and info.content_sha1 != "none":
        remote_hash = info.content_sha1
        algo = "sha1"
    else:
        logger.error(f"verify_file: {base_filename}: no remote hash")
        return False

    local_hash = get_file_hash(filename, algo)

    logger.debug(f'verify_file: {base_filename}: local {algo} "{local_hash}", remote {remote_hash}')
    return local_hash == remote_hash


def send_file(bucket: Bucket, filename: Path):
    """
    Send a file to a bucket
    :param bucket: The target buck
    :param filename: The path to the file to upload
    """
    base_filename = filename.name

    versions = list(bucket.list_file_versions(base_filename))
    if versions:
        if verify_file(bucket, filename, base_filename):
            logger.warning(f"send_file: {base_filename} already exists and is identical, not overwriting", )
            return
        else:
            logger.warning(f"send_file: {base_filename} already exists on B2, overwriting")

            for v in versions:
                v.delete()

    file_hash = get_file_hash(filename, "sha1")

    bucket.upload_local_file(str(filename), base_filename, progress_listener=ProgressListener(base_filename),
                             sha1_sum=file_hash)


def encryption_worker(queues: Dict[str, Queue]):
    """
    Encrypts things from the queues
    :param queues: Dictionary of queues
    """
    start_time = time()
    counter = 0
    for filename, gpg_key, comp_path in iter(queues["gpg_queue"].get, "STOP"):
        counter += 1
        crypt_start_time = time()
        logger.info(f"encryption_worker: encrypting {filename}")
        result = encrypt_file(filename, gpg_key, comp_path)
        queues["send_queue"].put(result)
        queues["unlink_queue"].put(filename)
        logger.debug(f"encryption_worker: encrypted {filename} in {time() - crypt_start_time:.2f} seconds")
    logger.debug(f"encryption_worker: queue is empty, terminating after {counter} items in {time() - start_time:.2f} "
                 f"seconds")
    sleep(5)  # settle


def sending_worker(queues: Dict[str, Queue], access_key: str, shared_key: str, host: str):
    """
    Sends things from the queues
    :param queues: Dictionary of queues
    :param access_key: B2 access key
    :param shared_key: B2 shared key
    :param host: host
    """
    start_time = time()
    counter = 0
    for filename in iter(queues["send_queue"].get, "STOP"):
        sending_start = time()
        counter += 1
        retry_count = 0
        max_retries = 10
        done = False

        while retry_count <= max_retries and not done:
            try:
                logger.info(f"sending_worker: sending {filename}")
                bucket = open_b2(access_key, shared_key, host)
                send_file(bucket, filename)
                done = True
            except B2Error as e:
                retry_count += 1
                sleep_time = 2 ** retry_count
                logger.error(f"sending_worker: exception {e}, retrying in {sleep_time} seconds ({retry_count}/"
                             f"{max_retries})")
                logger.exception(e)
                sleep(sleep_time)

        if not done:
            # trip out
            logger.error(f"sending_worker: could not upload {filename} in {retry_count} retries")
        else:
            size = filename.stat().st_size
            sending_seconds = time() - sending_start
            bytes_per_second = size / sending_seconds
            logger.debug(f"sending_worker: sent {filename} in {sending_seconds} seconds at "
                         f"{sizeof_fmt(bytes_per_second)}/second.")
            queues["unlink_queue"].put(filename)

    logger.debug(f"sending_worker: queue is empty, terminating after {counter} items in {time() - start_time} seconds")
    sleep(5)  # settle


def unlink_worker(queues: Dict[str, Queue]):
    """
    Unlink things from the queue
    :param queues: Dictionary of queues
    """
    start_time = time()
    counter = 0
    for filename in iter(queues["unlink_queue"].get, "STOP"):
        counter += 1
        logger.debug(f"unlink_worker: deleting {filename}")
        try:
            filename.unlink()
        except FileNotFoundError as e:
            logger.warning(f"unlink_worker: caught exception: {e}")

    logger.debug(f"unlink_worker: queue is empty, terminating after {counter} items in {time() - start_time} seconds")
    sleep(5)  # settle


def workers(queues: Dict[str, Queue], host: str, out_loc: Path, bkup_num: int,
            beginning: time, msg: str, process_count: int = None):
    """
    Manage workers for archiving
    :param queues: Dictionary of queues
    :param host: Host name
    :param out_loc: The temporary location path
    :param bkup_num: The backup number to archive
    :param beginning: The beginning time to write on COMPLETED file
    :param msg: Log message to write on COMPLETED file
    :param process_count: Number of parallels workers
    """
    # Start some handlers, wait until everything is done
    if not process_count:
        try:
            process_count = cpu_count()
        except NotImplementedError:
            process_count = 1

    encryption_procs = []
    for ep in range(process_count):
        p = Process(name=f"encryption_worker_{ep}", target=encryption_worker,
                    args=(queues,))
        queues["gpg_queue"].put("STOP")
        p.start()
        encryption_procs.append(p)

    send_procs = []
    for sp in range(ceil(process_count/2)):
        p = Process(name=f"send_worker_{sp}", target=sending_worker,
                    args=(queues, secrets.access_key, secrets.shared_key, host))
        p.start()
        send_procs.append(p)

    unlink_procs = []
    for up in range(ceil(process_count/4)):
        p = Process(name=f"unlink_worker_{up}", target=unlink_worker, args=(queues,))
        p.start()
        unlink_procs.append(p)

    send_queue_closed = False
    unlink_queue_closed = False

    for ep in encryption_procs:
        # wait for each process to terminate in turn
        ep.join()
        logger.debug(f"workers: process terminated: {ep.name}")

        if not next(filter(lambda e: e.is_alive(), encryption_procs), None) and not send_queue_closed:
            # crypto is done, close up the send queue
            logger.debug("workers: queuing final file")
            final_file = out_loc / f"{host}.{bkup_num}.tar.COMPLETE"
            with open(final_file, "w") as fp:
                fp.write(f'{beginning} {time()} "{msg}"')
            queues["send_queue"].put(final_file)

            logger.debug("workers: queuing stop sentinel for send_queue")
            for _ in send_procs:
                queues["send_queue"].put("STOP")
            send_queue_closed = True

        if send_queue_closed:
            for sp in send_procs:
                sp.join()
                logger.debug(f"workers: process terminated: {sp.name}")

                if not next(filter(lambda s: s.is_alive(), send_procs), None) and not unlink_queue_closed:
                    # sending is done, close up the unlink queue
                    logger.debug("workers: queuing stop sentinel for unlink_queue")
                    for _ in unlink_procs:
                        queues["unlink_queue"].put("STOP")
                    unlink_queue_closed = True

                if unlink_queue_closed:
                    for up in unlink_procs:
                        up.join()
                        logger.debug(f"workers: process terminated: {up.name}")

    for qname, q in queues.items():
        sleep(5)  # settle
        if not q.empty():
            logger.critical(f"workers: queue {qname} not empty!")
            raise Exception(f"queue not empty: {qname}")
        else:
            logger.debug(f"workers: queue {qname} is empty")


def archive(tar_create: Path, split_path: Path, par_path: Path, host: str, bkup_num: int, comp_path: Path,
            file_ext: str, split_size: int, out_loc: Path, par_file: int, share: str, jobs: int = None):
    """
    Archie a host to a B2 storage
    :param tar_create: The path to the tar binary
    :param split_path: The path to the split binary
    :param par_path: The path to the parity binary  (not used)
    :param host: The host name
    :param bkup_num: The backup number to archive
    :param comp_path: The compression binary
    :param file_ext: The extension assigned to the compression type (not used)
    :param split_size: The archive split size
    :param out_loc: The temporary location path
    :param par_file: The amount of parity data to create (not used)
    :param share: Backup share to archive
    """
    beginning = time()

    # Create queues for workers
    queues = {
        "gpg_queue": Queue(),
        "send_queue": Queue(),
        "unlink_queue": Queue(),
    }

    g = list(out_loc.glob(f"{host}.*.tar.*"))
    file_glob = ""
    # Is there already evidence of this having been done before?
    if g:
        logger.warning("main: finishing previous incomplete run")
        some_file = g[0].name
        r = search(rf"{escape(host)}\.-?([0-9]+)\.tar\..*", some_file)
        bkup_num = int(r.groups()[0])

        file_glob = ".*"

        msg = f"Continuing upload for host {host}, backup #{bkup_num}"
        if split_size > 0:
            msg += f", split into {split_size} byte chunks"
        if secrets.gpg_symmetric_key:
            msg += ", encrypted with secret key"
        logger.info(f"main: {msg}")
    else:
        msg = f"Writing archive for host {host}, backup #{bkup_num}"

        tar_cmd = [str(tar_create), "-t"]
        tar_cmd.extend(["-h", host])
        tar_cmd.extend(["-n", str(bkup_num)])
        tar_cmd.extend(["-s", share])
        tar_cmd.extend(["."])

        split_cmd = None
        outfile = out_loc / f"{host}.{bkup_num}.tar"

        if split_size > 0:
            file_glob = ".*"
            split_cmd = [str(split_path), "-b", str(split_size), "-", str(out_loc / f"{host}.{bkup_num}.tar.")]
            msg += f", split into {split_size} byte chunks"

        if secrets.gpg_symmetric_key:
            msg += ", encrypted with secret key"

        logger.info(f"main: {msg}")
        logger.debug(f"main: executing tar_cmd: {' '.join(tar_cmd)} > {outfile}")

        tar_fp = open(outfile, "wb")
        proc = Popen(tar_cmd, preexec_fn=lambda: nice(10), stdout=tar_fp)
        proc.communicate()
        tar_fp.close()

        if split_cmd:
            logger.debug(f"main: executing split_cmd: {' '.join(split_cmd)}")
            tar_fp = open(outfile, "rb")
            proc = Popen(split_cmd, preexec_fn=lambda: nice(10), stdin=tar_fp)
            proc.communicate()
            tar_fp.close()
            queues["unlink_queue"].put(outfile)

    file_glob = list(out_loc.glob(f"{host}.{bkup_num}.tar{file_glob}"))

    logger.info(f"main: dumped {len(file_glob)} files from {host} #{bkup_num}")

    # Pre-run to check for artifacts
    for i in file_glob:
        gpg_file = i.with_suffix(i.suffix + ".gpg")
        if not i.name.endswith(".gpg") and gpg_file.exists():
            logger.warning(f"main: orphaned GPG file being deleted: {gpg_file}")
            gpg_file.unlink()

    # Run again to send files to the relevant queue
    for i in sorted(file_glob):
        if (secrets.gpg_symmetric_key
                and not i.name.endswith(".gpg")
                and not i.name.endswith(".COMPLETE")):
            # A tar file, unencrypted, needs encrypted.
            logger.debug(f"main: adding {i} to gpg_queue")
            queues["gpg_queue"].put([i, secrets.gpg_symmetric_key, comp_path])
        else:
            # either encryption is off, or the file is already encrypted
            logger.debug(f"main: adding {i} to send_queue")
            queues["send_queue"].put(i)

    workers(queues, host, out_loc, bkup_num, beginning, msg, jobs)
    logger.info(f"main: completed run after {time() - beginning} seconds")


def main():
    # Read in arguments, verify that they match the BackupPC standard exactly
    parser = ArgumentParser(description="Archive a BackupPC host into B2")
    parser.add_argument("tarCreatePath", type=exec_path, help="Path to the tar binary")
    parser.add_argument("splitPath", type=exec_path, help="Path to the split binary")
    parser.add_argument("parPath", type=exec_path, help="The path to the parity binary  (not used)")
    parser.add_argument("host", type=str, help="Host name to backup")
    parser.add_argument("bkupNum", type=int, help="Backup number to archive")
    parser.add_argument("compPath", type=exec_path, help="Compression binary")
    parser.add_argument("fileExt", type=str, help="The extension assigned to the compression type (not used)")
    parser.add_argument("splitSize", type=int, help="Archive split size")
    parser.add_argument("outLoc", type=dir_path, help="Temporary location path")
    parser.add_argument("parFile", type=int, help="The amount of parity data to create (not used)")
    parser.add_argument("share", type=str, help="Backup share to archive")
    parser.add_argument("-v", "--verbose", action="store_const", dest="loglevel", const=INFO, default=WARNING,
                        help="Set log to info level")
    parser.add_argument("-d", "--debug", action="store_const", dest="loglevel", const=DEBUG,
                        help="Set log to debug level")
    parser.add_argument("-j", "--jobs", type=positive_int, dest="jobs", default=None,
                        help="Number of process to run in parallel, default to the number of core in the system")
    args = parser.parse_args()

    logger.setLevel(args.loglevel)

    archive(args.tarCreatePath, args.splitPath, args.parPath, args.host, args.bkupNum, args.compPath, args.fileExt,
            args.splitSize, args.outLoc, args.parFile, args.share, args.jobs)


if __name__ == "__main__":
    main()
