# Copyright 2020 Google LLC
# Modifications copyright 2021 FixReverter
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Module for processing crashes."""

import collections
import os
import re
import itertools

from clusterfuzz import stacktraces

from common import logs
from common import new_process
from common import sanitizer
from experiment.measurer import run_coverage

logger = logs.Logger('fixreverter_run_crashes')

Crash = collections.namedtuple('Crash', [
    'crash_testcase', 'triggers'
])

SIZE_REGEX = re.compile(r'\s([0-9]+|{\*})$', re.DOTALL)
CPLUSPLUS_TEMPLATE_REGEX = re.compile(r'(<[^>]+>|<[^\n]+(?=\n))')


def _filter_crash_type(crash_type):
    """Filters crash type to remove size numbers."""
    return SIZE_REGEX.sub('', crash_type)


def _filter_crash_state(crash_state):
    """Filters crash state to remove simple templates e.g. <int>."""
    return CPLUSPLUS_TEMPLATE_REGEX.sub('', crash_state)

def isCrash(result, app_binary):
    if not result.output:
        # Hang happened, no crash. Bail out.
        return False

    # Process the crash stacktrace from output.
    fuzz_target = os.path.basename(app_binary)
    stack_parser = stacktraces.StackParser(fuzz_target=fuzz_target,
                                           symbolized=True,
                                           detect_ooms_and_hangs=True,
                                           include_ubsan=True)
    crash_result = stack_parser.parse(result.output)
    if not crash_result.crash_state:
        # No crash occurred. Bail out.
        return False

    if crash_result.crash_type in ('Timeout', 'Out-of-memory'):
        # Uninteresting crash types for fuzzer efficacy. Bail out.
        return False

    return True



def process_crash(app_binary, crash_testcase_path, crashes_dir):
    """Returns the crashing unit in coverage_binary_output."""
    crash_filename = os.path.basename(crash_testcase_path)
    if (crash_filename.startswith('oom-') or
            crash_filename.startswith('timeout-')):
        # Don't spend time processing ooms and timeouts as these are
        # uninteresting crashes anyway. These are also excluded below, but don't
        # process them in the first place based on filename.
        return []

    # Run the crash with sanitizer options set in environment.
    env = os.environ.copy()
    sanitizer.set_sanitizer_options(env)
    command = [
        app_binary,
        '-timeout=%d' % run_coverage.UNIT_TIMEOUT,
        '-rss_limit_mb=%d' % run_coverage.RSS_LIMIT_MB, crash_testcase_path
    ]

    app_binary_dir = os.path.dirname(app_binary)
    result = new_process.execute(command,
                                 env=env,
                                 cwd=app_binary_dir,
                                 expect_zero=False,
                                 kill_children=True,
                                 timeout=run_coverage.UNIT_TIMEOUT + 5)

    if not isCrash(result, app_binary):
        return []

    triggers = parseFixReverterLog(result.output)
    # skip if crashed without triggering an injection
    if len(triggers) == 0:
        return []

    crashes = []

    for n in range(1, len(triggers)+1):
        for currset in itertools.combinations(triggers, n):
            # skip if current set is superset of a crash set
            isSuper = False
            for crash in crashes:
                if set(currset).issuperset(crash):
                    isSuper = True
                    break
            if isSuper:
                continue
            
            env["FIXREVERTER"] = 'on ' + ' '.join([str(i) for i in currset])
            currsetResult = new_process.execute(command,
                                 env=env,
                                 cwd=app_binary_dir,
                                 expect_zero=False,
                                 kill_children=True,
                                 timeout=run_coverage.UNIT_TIMEOUT + 5)
            
            if isCrash(currsetResult, app_binary):
                crashes.append(currset)

    return crashes

def parseFixReverterLog(output: list) -> set:
  lines = output.split('\n')
  triggers = set()
  for line in lines:
    if 'triggered bug index' in line:
      injectionID = int(line.split(' ')[-1])
      triggers.add(injectionID)
  return triggers

def _get_crash_key(crash_result):
    return '+'.join(str(i) for i in sorted(crash_result.triggers))



def do_crashes_run(app_binary, crashes_dir):
    """Does a crashes run of |app_binary| on |crashes_dir|. Returns a list of
    unique crashes."""
    crashes = {}
    for root, _, filenames in os.walk(crashes_dir):
        for filename in filenames:
            crash_testcase_path = os.path.join(root, filename)
            crashesets = process_crash(app_binary, crash_testcase_path, crashes_dir)
            for crashset in crashesets:
                crash = Crash(crash_testcase=os.path.relpath(crash_testcase_path, crashes_dir),
                    triggers=crashset)
                crashes[_get_crash_key(crash)] = crash
    return crashes
