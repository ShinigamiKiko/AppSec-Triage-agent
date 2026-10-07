"""What each language's framework starts without a call from project code.

A package the framework hands control to has no caller in project code by
construction; "nothing in the project calls it" closes nothing for it.
"""

from . import go, js, php

READERS = {"php": php.framework_invoked, "go": go.framework_invoked, "js": js.framework_invoked}
