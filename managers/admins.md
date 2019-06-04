# Administrators

Administrators is a manager implemented by `admins` that sets the field `Cmd.IsAdmin` according a list of administrators stored in it.

The `managerKF` method defines the `Cmd.IsAdmin` value, according the presence of the user that created it in the `admins.admins` slice, when `Cmd.Cmd = isAdminK`. If the value of `Cmd.User` isn't defined, then it leaves the command ready for `ipUser` to define that value.
