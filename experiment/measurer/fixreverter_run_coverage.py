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

from clusterfuzz import stacktraces

from common import logs
from common import new_process
from common import sanitizer
from experiment.measurer import run_coverage

logger = logs.Logger('run_crashes')

Crash = collections.namedtuple('Crash', [
    'crash_testcase', 'crash_type', 'crash_address', 'crash_state',
    'crash_stacktrace'
])

SIZE_REGEX = re.compile(r'\s([0-9]+|{\*})$', re.DOTALL)
CPLUSPLUS_TEMPLATE_REGEX = re.compile(r'(<[^>]+>|<[^\n]+(?=\n))')


def _filter_crash_type(crash_type):
    """Filters crash type to remove size numbers."""
    return SIZE_REGEX.sub('', crash_type)


def _filter_crash_state(crash_state):
    """Filters crash state to remove simple templates e.g. <int>."""
    return CPLUSPLUS_TEMPLATE_REGEX.sub('', crash_state)


def process_coverage(app_binary, testcase_path, new_units_dir):
    """Returns the crashing unit in coverage_binary_output."""

    # Run the crash with sanitizer options set in environment.
    env = os.environ.copy()
    sanitizer.set_sanitizer_options(env)
    command = [
        app_binary,
        '-timeout=%d' % run_coverage.UNIT_TIMEOUT,
        '-rss_limit_mb=%d' % run_coverage.RSS_LIMIT_MB, testcase_path
    ]
    app_binary_dir = os.path.dirname(app_binary)
    result = new_process.execute(command,
                                 env=env,
                                 cwd=app_binary_dir,
                                 expect_zero=False,
                                 kill_children=True,
                                 timeout=run_coverage.UNIT_TIMEOUT + 5)

    return parseFixReverterLog(result.output)

def parseFixReverterLog(output: list) -> set:
  lines = output.split('\n')
  reaches = set()
  triggers = set()
  for line in lines:
    if 'triggered bug index' in line:
      injectionID = int(line.split(' ')[-1])
      reaches.add(injectionID)
      triggers.add(injectionID)
    elif 'reached bug index' in line:
      injectionID = int(line.split(' ')[-1])
      reaches.add(injectionID)
  return FixReverterCov(reaches, triggers)

def _get_crash_key(crash_result):
    """Return a unique identifier for a crash."""
    return f'{crash_result.crash_type}:{crash_result.crash_state}'

FixReverterCov = collections.namedtuple('FixReverterCov', ['reaches', 'triggers'])

def do_coverage_run(app_binary, new_units_dir):
    """Does a crashes run of |app_binary| on |new_units_dir|. Returns a list of
    unique crashes."""

    reaches = set()
    triggers = set()
    for root, _, filenames in os.walk(new_units_dir):
      for filename in filenames:
        testcase_path = os.path.join(root, filename)
        cov = process_coverage(app_binary, testcase_path, new_units_dir)
        reaches.update(cov.reaches)
        triggers.update(cov.triggers)

    return FixReverterCov(reaches, triggers)
