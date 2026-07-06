using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using EnterpriseFileSecurity.Common;

namespace EnterpriseFileSecurity.USB.Services;

public class HotPlugStateManager
{
    private readonly ConcurrentDictionary<string, HotPlugState> _stateMachine = new();
    private readonly ConcurrentDictionary<string, DateTime> _debounceMap = new();
    private readonly ConcurrentDictionary<string, string> _fingerprintIndex = new();
    private readonly TimeSpan DebounceInterval = TimeSpan.FromMilliseconds(800);
    private readonly TimeSpan StateTimeout = TimeSpan.FromSeconds(5);

    public bool HandleDeviceInsert(UsbDeviceInfo deviceInfo)
    {
        if (string.IsNullOrEmpty(deviceInfo.PnpDeviceID)) return false;

        if (_debounceMap.TryGetValue(deviceInfo.PnpDeviceID, out var lastEventTime))
        {
            if (DateTime.UtcNow - lastEventTime < DebounceInterval) return false;
        }
        _debounceMap[deviceInfo.PnpDeviceID] = DateTime.UtcNow;

        if (_stateMachine.TryGetValue(deviceInfo.PnpDeviceID, out var existingState))
        {
            if (existingState.CurrentPhase == DevicePhase.Removing)
            {
                existingState.CurrentPhase = DevicePhase.Active;
                existingState.PhaseEnteredAt = DateTime.UtcNow;
                existingState.RapidReinsertCount++;
                return true;
            }
            if (existingState.CurrentPhase == DevicePhase.Active) return false;
            if (existingState.CurrentPhase == DevicePhase.Blocked) return false;
        }

        _stateMachine[deviceInfo.PnpDeviceID] = new HotPlugState
        {
            PnpDeviceID = deviceInfo.PnpDeviceID,
            DeviceFingerprint = deviceInfo.ComputeFingerprint(),
            CurrentPhase = DevicePhase.Connecting,
            PhaseEnteredAt = DateTime.UtcNow
        };
        _fingerprintIndex[deviceInfo.ComputeFingerprint()] = deviceInfo.PnpDeviceID;
        return true;
    }

    public void HandleDeviceRemove(UsbDeviceInfo deviceInfo)
    {
        if (string.IsNullOrEmpty(deviceInfo.PnpDeviceID)) return;
        if (_stateMachine.TryGetValue(deviceInfo.PnpDeviceID, out var state))
        {
            state.CurrentPhase = DevicePhase.Removing;
            state.PhaseEnteredAt = DateTime.UtcNow;
            Task.Run(async () =>
            {
                await Task.Delay(3000);
                _stateMachine.TryRemove(deviceInfo.PnpDeviceID, out _);
                _fingerprintIndex.TryRemove(state.DeviceFingerprint, out _);
                _debounceMap.TryRemove(deviceInfo.PnpDeviceID, out _);
            });
        }
    }

    public void MarkBlocked(string pnpDeviceID)
    {
        if (_stateMachine.TryGetValue(pnpDeviceID, out var state))
            state.CurrentPhase = DevicePhase.Blocked;
    }

    private enum DevicePhase { Connecting, Active, Blocked, Removing }

    private class HotPlugState
    {
        public string PnpDeviceID { get; set; }
        public string DeviceFingerprint { get; set; }
        public DevicePhase CurrentPhase { get; set; }
        public DateTime PhaseEnteredAt { get; set; }
        public int RapidReinsertCount { get; set; }
    }
}
