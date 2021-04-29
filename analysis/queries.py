# Copyright 2020 Google LLC
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
"""Database queries for acquiring experiment data."""

import pandas as pd

from sqlalchemy import and_, func

from database.models import Experiment, Trial, Snapshot, Crash, FixReverterReach, FixReverterTrigger, FixReverterCrash
from database import utils as db_utils


def get_experiment_data(experiment_names):
    """Get measurements (such as coverage) on experiments from the database."""

    concat_crash = db_utils.query(
        Crash.time, Crash.trial_id, func.group_concat(Crash.crash_key).label("crashes")).group_by(Crash.time, Crash.trial_id).subquery()

    concat_fr_reach = db_utils.query(
        FixReverterReach.time, FixReverterReach.trial_id, func.group_concat(FixReverterReach.fixreverter_reach_key.op(',')(text('"+"'))).label("fr_reaches")).group_by(FixReverterReach.time, FixReverterReach.trial_id).subquery()
    concat_fr_trigger = db_utils.query(
        FixReverterTrigger.time, FixReverterTrigger.trial_id, func.group_concat(FixReverterTrigger.fixreverter_trigger_key.op(',')(text('"+"'))).label("fr_triggers")).group_by(FixReverterTrigger.time, FixReverterTrigger.trial_id).subquery()
    concat_fr_crash = db_utils.query(
        FixReverterCrash.time, FixReverterCrash.trial_id, func.group_concat(FixReverterCrash.fixreverter_crash_key.op(',')(text('"+"'))).label("fr_crashes")).group_by(FixReverterCrash.time, FixReverterCrash.trial_id).subquery()

    snapshots_query = db_utils.query(
        Experiment.git_hash, Experiment.experiment_filestore,
        Trial.experiment, Trial.fuzzer, Trial.benchmark,
        Trial.time_started, Trial.time_ended,
        Snapshot.trial_id, Snapshot.time, Snapshot.edges_covered,
        Snapshot.fuzzer_stats, concat_crash.c.crashes,
        concat_fr_reach.c.fr_reaches,concat_fr_trigger.c.fr_triggers, concat_fr_crash.c.fr_crashes)\
        .select_from(Experiment)\
        .join(Trial)\
        .join(Snapshot)\
        .join(concat_crash,
              and_(Snapshot.time == concat_crash.c.time,
                   Snapshot.trial_id == concat_crash.c.trial_id), isouter=True)\
        .join(concat_fr_reach,
              and_(Snapshot.time == concat_fr_reach.c.time,
                   Snapshot.trial_id == concat_fr_reach.c.trial_id), isouter=True)\
        .join(concat_fr_trigger,
              and_(Snapshot.time == concat_fr_trigger.c.time,
                   Snapshot.trial_id == concat_fr_trigger.c.trial_id), isouter=True)\
        .join(concat_fr_crash,
              and_(Snapshot.time == concat_fr_crash.c.time,
                   Snapshot.trial_id == concat_fr_crash.c.trial_id), isouter=True)\
        .filter(Experiment.name.in_(experiment_names))\
        .filter(Trial.preempted.is_(False))

    return pd.read_sql_query(snapshots_query.statement, db_utils.engine)


def get_experiment_description(experiment_name):
    """Get the description of the experiment named by |experiment_name|."""
    # Do another query for the description so we don't explode the size of the
    # results from get_experiment_data.
    return db_utils.query(Experiment.description)\
            .select_from(Experiment)\
            .filter(Experiment.name == experiment_name).one()


def add_nonprivate_experiments_for_merge_with_clobber(experiment_names):
    """Returns a new list containing experiment names preeceeded by a list of
    nonprivate experiments in the order in which they were run, such that
    these nonprivate experiments executed before. This is useful
    if you want to combine reports from |experiment_names| and all nonprivate
    experiments."""
    earliest_creation_time = None
    for result in db_utils.query(Experiment.time_created).filter(
            Experiment.name.in_(experiment_names)):
        experiment_creation_time = result[0]
        if not earliest_creation_time:
            earliest_creation_time = experiment_creation_time
        else:
            earliest_creation_time = min(earliest_creation_time,
                                         experiment_creation_time)

    nonprivate_experiments = db_utils.query(Experiment.name).filter(
        ~Experiment.private, ~Experiment.name.in_(experiment_names),
        ~Experiment.time_ended.is_(None),
        Experiment.time_created <= earliest_creation_time).order_by(
            Experiment.time_created)
    nonprivate_experiment_names = [
        result[0] for result in nonprivate_experiments
    ]

    return nonprivate_experiment_names + experiment_names
