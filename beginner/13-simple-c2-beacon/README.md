# 13 — Simple C2 Beacon (Python, offline lab)

The upstream beacon is reimplemented as a timing simulator and detector. No sockets, callbacks, or host control are present.

## Run

```powershell
python beacon_lab.py simulate -n 10 --interval 60 --jitter 0.2
python beacon_lab.py detect events.txt
```

`events.txt` contains one ISO-8601 timestamp per line.

## Detection

Gaps between events are analysed with the median absolute deviation. A stable interval with low variation is scored as suspicious when there are at least five gaps.

## Test

```powershell
python -m unittest discover -s tests -v
```

7 tests, standard library only. All events are synthetic.
