# Copyright (C) 2019 The Raphielscape Company LLC.
#
# Licensed under the Raphielscape Public License, Version 1.c (the "License");
# you may not use this file except in compliance with the License.
#
""" Userbot module for executing code and terminal commands from Telegram. """

import asyncio
import io
import re
import sys
import traceback
from getpass import getuser
from os import remove
from sys import executable

from userbot import CMD_HELP, TERM_ALIAS
from userbot.events import register


@register(outgoing=True, pattern=r"^\.eval(?: |$|\n)([\s\S]*)")
async def _(event):
    if event.fwd_from:
        return
    s_m_ = await event.edit("Processing ...")
    cmd = event.pattern_match.group(1)
    if not cmd:
        return await s_m_.edit("`What should i eval...`")

    old_stderr = sys.stderr
    old_stdout = sys.stdout
    redirected_output = sys.stdout = io.StringIO()
    redirected_error = sys.stderr = io.StringIO()
    stdout, stderr, exc = None, None, None

    try:
        returned = await aexec(cmd, s_m_)
    except Exception:
        exc = traceback.format_exc()

    stdout = redirected_output.getvalue()
    stderr = redirected_error.getvalue()
    sys.stdout = old_stdout
    sys.stderr = old_stderr

    evaluation = "No Output"
    if exc:
        evaluation = exc
    elif stderr:
        evaluation = stderr
    elif stdout:
        evaluation = stdout
    elif returned:
        evaluation = returned

    final_output = f"**EVAL**: \n`{cmd}` \n\n**OUTPUT**: \n`{evaluation}` \n"

    if len(final_output) >= 4096:
        with io.BytesIO(str.encode(final_output)) as out_file:
            out_file.name = "eval.txt"
            await s_m_.reply(cmd, file=out_file)
            await event.delete()
    else:
        await s_m_.edit(final_output)


async def aexec(code, smessatatus):
    message = event = smessatatus

    reply = await event.get_reply_message()
    exec(
        f"async def __aexec(message, reply, client): "
        + "\n event = smessatatus = message"
        + "".join(f"\n {l}" for l in code.split("\n"))
    )
    return await locals()["__aexec"](message, reply, message.client)


@register(outgoing=True, pattern=r"^\.exec(?: |$|\n)([\s\S]*)")
async def run(run_q):
    """For .exec command, which executes the dynamically created program"""
    code = run_q.pattern_match.group(1)

    if run_q.is_channel and not run_q.is_group:
        return await run_q.edit("`Exec isn't permitted on channels!`")

    if not code:
        return await run_q.edit(
            "``` At least a variable is required to"
            "execute. Use .help exec for an example.```"
        )

    if code in ("userbot.session", "config.env"):
        return await run_q.edit("`That's a dangerous operation! Not Permitted!`")

    if len(code.splitlines()) <= 5:
        codepre = code
    else:
        clines = code.splitlines()
        codepre = (
            clines[0] + "\n" + clines[1] + "\n" + clines[2] + "\n" + clines[3] + "..."
        )

    command = "".join(f"\n {l}" for l in code.split("\n.strip()"))
    process = await asyncio.create_subprocess_exec(
        executable,
        "-c",
        command.strip(),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    result = str(stdout.decode().strip()) + str(stderr.decode().strip())

    if result:
        if len(result) > 4096:
            file = open("output.txt", "w+")
            file.write(result)
            file.close()
            await run_q.client.send_file(
                run_q.chat_id,
                "output.txt",
                reply_to=run_q.id,
                caption="`Output too large, sending as file`",
            )
            remove("output.txt")
            return
        await run_q.edit(
            "**Query: **\n`" f"{codepre}" "`\n**Result: **\n`" f"{result}" "`"
        )
    else:
        await run_q.edit(
            "**Query: **\n`" f"{codepre}" "`\n**Result: **\n`No result returned/False`"
        )


@register(outgoing=True, pattern=r"^\.term(?: |$|\n)(.*)")
async def terminal_runner(term):
    """For .term command, runs bash commands and scripts on your server."""
    curruser = TERM_ALIAS if TERM_ALIAS else getuser()
    command = term.pattern_match.group(1)
    try:
        from os import geteuid

        uid = geteuid()
    except ImportError:
        uid = "This ain't it chief!"

    if term.is_channel and not term.is_group:
        return await term.edit("`Term commands aren't permitted on channels!`")

    if not command:
        return await term.edit(
            "``` Give a command or use .help term for an example.```"
        )

    for i in ("userbot.session", "env"):
        if command.find(i) != -1:
            return await term.edit("`That's a dangerous operation! Not Permitted!`")

    if not re.search(r"echo[ \-\w]*\$\w+", command) is None:
        return await term.edit("`That's a dangerous operation! Not Permitted!`")

    process = await asyncio.create_subprocess_shell(
        command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    result = str(stdout.decode().strip()) + str(stderr.decode().strip())

    if len(result) > 4096:
        output = open("output.txt", "w+")
        output.write(result)
        output.close()
        await term.client.send_file(
            term.chat_id,
            "output.txt",
            reply_to=term.id,
            caption="`Output too large, sending as file`",
        )
        remove("output.txt")
        return

    if uid == 0:
        await term.edit(f"`{curruser}:~# {command}\n{result}`")
    else:
        await term.edit(f"`{curruser}:~$ {command}\n{result}`")

@register(outgoing=True, pattern=r"^\.r(?: |$|\n)([\s\S]*)")
async def _exec_term(message):
    """ run commands in shell (terminal with live update) """
    await message.edit("`Executing terminal ...`")
    cmd = message.pattern_match.group(1)

    try:
        parsed_cmd = cmd
    except Exception as e:  # pylint: disable=broad-except
        await message.edit(str(e))
        return
    try:
        t_obj = await Terminal.execute(parsed_cmd)  # type: Term
    except Exception as t_e:  # pylint: disable=broad-except
        await message.edit(str(t_e))
        return

    cur_user = getuser()
    uid = geteuid()

    prefix = f"**{cur_user}:~#**" if uid == 0 else f"**{cur_user}:~$**"
    output = f"{prefix} `{cmd}`\n"

    count = 0
    k = None
    while not t_obj.finished:
        count += 1
        await asyncio.sleep(0.3)
        if count >= 5:
            count = 0
            out_data = f"{prefix}`{t_obj.line}`"
            try:
                if not k:
                    k = await message.edit(out_data)
                else:
                    await k.edit(out_data)
            except Exception:
                pass

    out_data = f"{output}`{t_obj.output}`\n"
    await t_obj.wait(3)

    if len(out_data) > 4096:
        output = open("terminal.txt", "w+")
        output.write(out_data)
        output.close()
        await message.client.send_file(
            message.chat_id,
            "terminal.txt",
            reply_to=message.id,
            caption="`Output too large, sending as file`",
        )
        remove("terminal.txt")
        return
    else:
        await message.edit(out_data)
    del out_data

CMD_HELP.update(
    {
        "eval": ">`.eval print('world')`" "\nUsage: Just like exec.",
        "exec": ">`.exec print('hello')`" "\nUsage: Execute small python scripts.",
        "term": ">`.term <cmd>`",
        "run": ">`.r <cmd>`"
        "\nUsage: Run bash commands and scripts on your server.",
    }
)

try:
    from os import geteuid, setsid, getpgid, killpg
    from signal import SIGKILL
except ImportError:
    # pylint: disable=ungrouped-imports
    from os import kill as killpg
    from signal import CTRL_C_EVENT as SIGKILL

    def geteuid() -> int:
        return 1

    def getpgid(arg: Any) -> Any:
        return arg

    setsid = None

class Terminal:
    """ live update term class """

    def __init__(self, process: asyncio.subprocess.Process) -> None:
        self._process = process
        self._line = b''
        self._output = b''
        self._init = asyncio.Event()
        self._is_init = False
        self._cancelled = False
        self._finished = False
        self._loop = asyncio.get_running_loop()
        self._listener = self._loop.create_future()

    @property
    def line(self) -> str:
        return self._by_to_str(self._line)
    
    @property
    def output(self) -> str:
        return self._by_to_str(self._output)

    @staticmethod
    def _by_to_str(data: bytes) -> str:
        return data.decode('utf-8', 'replace').rstrip()

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    @property
    def finished(self) -> bool:
        return self._finished

    async def init(self) -> None:
        await self._init.wait()

    async def wait(self, timeout: int) -> None:
        self._check_listener()
        try:
            await asyncio.wait_for(self._listener, timeout)
        except asyncio.TimeoutError:
            pass

    def _check_listener(self) -> None:
        if self._listener.done():
            self._listener = self._loop.create_future()

    def cancel(self) -> None:
        if self._cancelled or self._finished:
            return
        killpg(getpgid(self._process.pid), SIGKILL)
        self._cancelled = True

    @classmethod
    async def execute(cls, cmd: str) -> 'Terminal':
        kwargs = dict(
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        if setsid:
            kwargs['preexec_fn'] = setsid
        process = await asyncio.create_subprocess_shell(cmd, **kwargs)
        t_obj = cls(process)
        t_obj._start()
        return t_obj

    def _start(self) -> None:
        self._loop.create_task(self._worker())

    async def _worker(self) -> None:
        if self._cancelled or self._finished:
            return
        await asyncio.wait([self._read_stdout(), self._read_stderr()])
        await self._process.wait()
        self._finish()

    async def _read_stdout(self) -> None:
        await self._read(self._process.stdout)

    async def _read_stderr(self) -> None:
        await self._read(self._process.stderr)

    async def _read(self, reader: asyncio.StreamReader) -> None:
        while True:
            line = await reader.read(n=1024)
            if not line:
                break
            self._append(line)

    def _append(self, line: bytes) -> None:
        self._line = line
        self._output += line
        self._check_init()

    def _check_init(self) -> None:
        if self._is_init:
            return
        self._loop.call_later(1, self._init.set)
        self._is_init = True

    def _finish(self) -> None:
        if self._finished:
            return
        self._init.set()
        self._finished = True
        if not self._listener.done():
            self._listener.set_result(None)