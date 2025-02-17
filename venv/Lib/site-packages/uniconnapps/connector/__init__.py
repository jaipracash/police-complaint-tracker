from __future__ import absolute_import

from . import core
from . import events
from . import actions


class UcaClient(core.BaseUcaClient, events.EventsMixin, actions.ActionsMixin):
  def __init__(self, *args, **kwargs):
    core.BaseUcaClient.__init__(self, *args, **kwargs)
    events.EventsMixin.__init__(self)
    actions.ActionsMixin.__init__(self)

