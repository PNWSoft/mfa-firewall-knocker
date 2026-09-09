Run `dotnet run --project tests/MFAService.RegressionTests -c Release` from the repository root.

The checks use the service's request and expiry logic with an in-memory firewall substitute.
The subprocess checks launch only this test executable in harmless child modes. No live
firewall commands run. Logs stay in the test output directory. Windows and Linux firewall
integration must still be exercised on disposable hosts before deployment.
