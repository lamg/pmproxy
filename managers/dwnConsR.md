# Download consupmtion restrictor

The _Download consumption restrictor_ is a manager that limits the amount of data that users can download in determined period of time. It's implemented by `dwnConsR`. The fields `lastReset` and `resetCycle` determine the date when all consumptions in `userCons` are set to 0. `resetCycle` is the duration of the period, and `lastReset` is the date of the last reset, which is updated everytime consumptions are reseted. When a consumption reaches the assigned quota for that period of time, the manager notifies it through its interface.

The interface for interacting with it is the `managerKF` method, which receives a command (`Cmd`) and processes it. Commands may be received without the information needed to be processed, in that case the method `managerKF` changes the field `Cmd.Manager` to have the name of the manager that can provide the absent information. Then the method `manager.exec` deals with delivering that command to the right manager, and returning it back to the manager that originated it.

`dwnConsR` processes the following commands
- `Get` returns the user's alias and name, groups, quota and consumption. In case the command doesn't have field `Cmd.Groups` defined it will change the manager to the value of `dwnConsR.userDBN`, which is expected to set it according to the user logged at Cmd.IP.
- `Set` sets the value of `Cmd.Uint64` as the consumption for the user sent at `Cmd.String`, if the command is sent by an administrator. If the value for `Cmd.IsAdmin` isn't defined it will change the manager for `adminsK` which is the one that has the administrators stored.
- `Show` serializes with JSON format the `dwnConsR` instance, writing it to Cmd.Data
