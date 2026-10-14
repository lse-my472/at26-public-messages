# MY472: public encrypted messages

This is a repository of encrypted messages from the instructor to students in MY472. This repository is public, so anyone can download every file in it. However, the files are all encrypted (and the students' ID numbers are anonymised), so the data in this repo is useless to the wider public.

More specifically:

- Each `.enc` file in the `replies` folder is an encrypted reply to a message that a student sent to the instructor. 
- Each of these files is named after a hash of the message it answers, so the name does not say who it is for. 
- Only the student who sent the message can decrypt the reply.
- `instructor_public_key.pem` is the instructor's public key, which is safe to publish.
- The replies are written by `bot.py`, which runs on a schedule (`.github/workflows/bot.yml`). 
- All code in this repo is public since knowing how the bot works does not help anyone read the replies.