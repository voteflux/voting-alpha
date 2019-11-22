import copy
import os
from typing import Dict, List

import yaml
from attrdict import AttrDict


StackStateTy = dict
StateTy = Dict[str, StackStateTy]
ParamsTy = Dict[str, str]


class StateTracker:
    def __init__(self, db_file="_manager_cache.yaml"):
        self.db_file = db_file
        self.states = []

    def read(self):
        return ManagerState(self.read_raw(), self)

    def read_raw(self) -> StateTy:
        if not os.path.exists(self.db_file):
            with open(self.db_file, 'w') as f:
                f.write('')
        with open(self.db_file, 'r') as f:
            return AttrDict(yaml.safe_load(f))

    def update(self, new_state_cache):
        with open(self.db_file, 'w') as f:
            yaml.safe_dump(new_state_cache, f)

    def _register_state_hook(self, ms):
        self.states.append(ms)

    def _hook_refresh(self):
        for ms in self.states:
            ms.refresh()


class ManagerState:
    def __init__(self, state_obj: StateTy, tracker: StateTracker):
        self._load_from_parsed(state_obj)
        self.tracker = tracker

    def _load_from_parsed(self, state_obj: StateTy):
        self.stack_cache: StateTy = state_obj
        self.stack_names = list(self.stack_cache.keys())

    def get_stack_names(self) -> List[str]:
        return self.stack_names

    def get_stack(self, stack_name) -> StackStateTy:
        if stack_name not in self.stack_names:
            raise Exception("Stack unknown")
        return self.stack_cache[stack_name]

    def refresh(self):
        self._load_from_parsed(self.tracker.read_raw())

    def _save(self, full_state_cache):
        self.tracker.update(full_state_cache)

    def _copy_cache(self):
        return copy.deepcopy(self.stack_cache)

    def save_stack_params(self, stack_name, params: ParamsTy, wipe_previous=False):
        new_cache = self._copy_cache()
        if 'params' not in new_cache[stack_name]:
            new_cache[stack_name]['params']: ParamsTy = {}
        new_cache[stack_name]['params'].update(params)
        self._save(new_cache)

    def get_stack_params(self, stack_name):
        return self.stack_cache[stack_name]['params']

    def _save_stack_property(self, stack_name, prop, data):
        new_cache = self._copy_cache()
        new_cache[stack_name][prop] = data
        self._save(new_cache)

    def _get_stack_property(self, stack_name, prop):
        return self.stack_cache[stack_name][prop]

    def save_stack_details(self, stack_name, details):
        return self._save_stack_property(stack_name, 'details', details)

    def get_stack_details(self, stack_name):
        return self._get_stack_property(stack_name, 'details')

    def save_stack_resources(self, stack_name, resources):
        return self._save_stack_property(stack_name, 'resources', resources)

    def get_stack_resources(self, stack_name):
        return self._get_stack_property(stack_name, 'resources')
