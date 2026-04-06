import mimetypes
import socket
import base64
import click
import ssl
import os

CRLF = '\r\n'

def read_response(f, verbose):
    lines = []
    while True:
        line = f.readline().rstrip('\r\n')
        if verbose: print('<<<', line)
        lines.append(line)
        if len(line) < 4 or line[3] == ' ':
            break
    code = int(lines[-1][:3])
    extensions = {line[4:].split()[0].upper() for line in lines[1:] if len(line) > 4}
    return code, extensions

def cmd(sock, f, line, verbose):
    if verbose: print('>>>', line)
    sock.sendall((line + CRLF).encode())
    code, _ = read_response(f, verbose)
    return code

def send_images(host, port, from_addr, to, subject, directory, use_ssl, user, password, verbose):
    # соединение
    raw_sock = socket.create_connection((host, port))

    if use_ssl and port == 465:
        # прямой SSL (SMTPS)
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(raw_sock, server_hostname=host)
    else:
        sock = raw_sock

    f = sock.makefile('r')
    read_response(f, verbose)

    # EHLO
    sock.sendall(('EHLO localhost' + CRLF).encode())
    code, extensions = read_response(f, verbose)

    # STARTTLS (только если сервер поддерживает и соединение ещё не зашифровано)
    if 'STARTTLS' in extensions and not isinstance(sock, ssl.SSLSocket):
        code = cmd(sock, f, 'STARTTLS', verbose)
        if code != 220:
            raise RuntimeError(f'STARTTLS отклонён: {code}')
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=host)
        f = sock.makefile('r')
        # повторный EHLO после TLS — теперь сервер вернёт AUTH
        sock.sendall(('EHLO localhost' + CRLF).encode())
        code, extensions = read_response(f, verbose)

    # авторизация (только после STARTTLS)
    if user:
        if 'AUTH' not in extensions:
            raise RuntimeError('Сервер не поддерживает AUTH')
        code = cmd(sock, f, 'AUTH LOGIN', verbose)
        if code != 334:
            raise RuntimeError(f'AUTH LOGIN отклонён: {code}')
        code = cmd(sock, f, base64.b64encode(user.encode()).decode(), verbose)
        if code != 334:
            raise RuntimeError(f'Логин отклонён: {code}')
        code = cmd(sock, f, base64.b64encode(password.encode()).decode(), verbose)
        if code != 235:
            raise RuntimeError(f'Неверный пароль или App Password: {code}')

    # собираем картинки
    exts = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
    images = [os.path.join(directory, fn) for fn in os.listdir(directory)
              if os.path.splitext(fn)[1].lower() in exts]

    # формируем письмо
    boundary = 'BOUND42'
    parts = (
        f'From: {from_addr}\r\nTo: {to}\r\nSubject: {subject}\r\n'
        f'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="{boundary}"\r\n\r\n'
        f'--{boundary}\r\nContent-Type: text/plain\r\n\r\nHappy Pictures!\r\n\r\n'
    )
    for image in images:
        mime, _ = mimetypes.guess_type(image)
        with open(image, 'rb') as fh:
            data = base64.encodebytes(fh.read()).decode()
        name = os.path.basename(image)
        parts += (
            f'--{boundary}\r\nContent-Type: {mime}; name="{name}"\r\n'
            f'Content-Disposition: attachment; filename="{name}"\r\n'
            f'Content-Transfer-Encoding: base64\r\n\r\n{data}\r\n'
        )
    parts += f'--{boundary}--\r\n'

    # Dot-stuffing (по рфс какому-то что бы короче всё не взорвалось)
    safe_parts = '\r\n'.join(
        ('.' + line if line.startswith('.') else line)
        for line in parts.split('\r\n')
    )

    # size
    size_ext = any(e.startswith('SIZE') for e in extensions)
    size_param = f' SIZE={len(safe_parts.encode())}' if size_ext else ''

    # SMTP-диалог
    if 'PIPELINING' in extensions:
        # отправляем три команды разом (это нам разрешает делать PIPELINING)
        pipeline = (
            f'MAIL FROM:<{from_addr}>{size_param}{CRLF}'
            f'RCPT TO:<{to}>{CRLF}'
            f'DATA{CRLF}'
        )
        if verbose:
            for line in [f'MAIL FROM:<{from_addr}>{size_param}', f'RCPT TO:<{to}>', 'DATA']:
                print('>>>', line)
        sock.sendall(pipeline.encode())

        # читаем три ответа по очереди
        code_mail, _ = read_response(f, verbose)
        if code_mail != 250:
            raise RuntimeError(f'MAIL FROM отклонён: {code_mail}')

        code_rcpt, _ = read_response(f, verbose)
        if code_rcpt != 250:
            raise RuntimeError(f'RCPT TO отклонён: {code_rcpt}')

        code_data, _ = read_response(f, verbose)
        if code_data != 354:
            raise RuntimeError(f'DATA отклонён: {code_data}')
    else:
        # старый путь без pipelining
        code = cmd(sock, f, f'MAIL FROM:<{from_addr}>{size_param}', verbose)
        if code != 250:
            raise RuntimeError(f'MAIL FROM отклонён: {code}')

        code = cmd(sock, f, f'RCPT TO:<{to}>', verbose)
        if code != 250:
            raise RuntimeError(f'RCPT TO отклонён: {code}')

        code = cmd(sock, f, 'DATA', verbose)
        if code != 354:
            raise RuntimeError(f'DATA отклонён: {code}')

    sock.sendall(safe_parts.encode())
    code = cmd(sock, f, '.', verbose)
    if code != 250:
        raise RuntimeError(f'Письмо не принято: {code}')

    cmd(sock, f, 'QUIT', verbose)
    sock.close()
    print('✓ Готово!')


# обработчики аргументов
@click.command()
@click.option('--ssl',       'use_ssl',   is_flag=True, default=False)
@click.option('-s', '--server',           required=True)
@click.option('-t', '--to',               required=True)
@click.option('-f', '--from',  'from_addr', default='')
@click.option('--subject',                default='Happy Pictures')
@click.option('--auth',                   is_flag=True, default=False)
@click.option('-v', '--verbose',          is_flag=True, default=False)
@click.option('-d', '--directory',        default='.', type=click.Path(exists=True))
def main(use_ssl, server, to, from_addr, subject, auth, verbose, directory):
    host, port = (server.rsplit(':', 1) if ':' in server else (server, None))
    port = int(port) if port else (465 if use_ssl else 25)

    user = password = None
    if auth:
        user     = click.prompt('Логин')
        password = click.prompt('Пароль', hide_input=True)

    send_images(host, port, from_addr, to, subject, directory, use_ssl, user, password, verbose)

if __name__ == '__main__':
    main()
