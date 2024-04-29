from asyncio import create_subprocess_exec
from asyncio.subprocess import PIPE

async def injectStringsToProcess(processFd, processId, command, escapedCommandCharacterLength=0):
    NEWLINE_CHARACTER = '\\n'
    ESCAPED_NEWLINE_CHARACTER_LENGTH = 1
    command += NEWLINE_CHARACTER
    commandLength = len(command) - ESCAPED_NEWLINE_CHARACTER_LENGTH - escapedCommandCharacterLength

    callWriteFunction = f'''call write({processFd}, "{command}", {commandLength})'''
    gdbCommands = [
        callWriteFunction,
        'detach',
        'quit'
    ]

    process = await create_subprocess_exec('gdb', '-p', str(processId),
                                                   stdin = PIPE,
                                                   stdout = PIPE,
                                                   stderr = PIPE)

    for gdbCommand in gdbCommands:
        formattedCommand = gdbCommand.encode('utf-8') + b'\n'
        process.stdin.write(formattedCommand)

    process.stdin.close()
    await process.wait()