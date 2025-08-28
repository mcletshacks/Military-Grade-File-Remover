Congratulations
you found a tool that doesnt just delete files.. it erases their memory from the fucking timeline

this is not a shredder
this is a goddamn data executioner

Each file gets overwritten with entropy
Renamed like its in witness protection
Timestamp mutilated then dumped in a grave under /input/.completed

No questions
No witnesses
No aftercare

---

## Setup

1 Put your sus files into /input
2 Confirm your lack of regret with

```
python main.py
```

If youre still human use --dry to simulate
If youre beyond redemption 2 --adv unlocks more magic

---

## Flags

```
--input PATH        Input folder default input
--threads N         Worker threads default is CPU count
--block N           Block size bytes default 1MB
--passes N          Overwrite passes default 7
--redo N            Retry attempts default 2
--delay N           Delay seconds between retries
--yes               Skips confirm promt
--verbose           Extra output during wipe
--strict            Exit with non zero if any file fails
--adv               Adds final pass of randomized magic
--dry               Simulate destruction dont touch files
```

---

## Notes

Thats no joke files are actually destroyed you will never beable to recover them
Each overwrite pass adds unique patterns, secrets, hash digests and HKDF streams
Metadata Timestamps get scrambled Names get replaced Existence gets revoked
Bigger files will need some time

---

## Warnings

If youre running this on anything important stop
If youre unsure whats inside /input stop
If you dont like irreversible actions stop

Otherwise
Lean back run it and watch it eat everything you feed it

---

Made by a sleep deprived dev who got tired of right click > recycle bin
