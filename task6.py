import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
from datetime import timezone, timedelta
import click
import getpass

# локальный часовой пояс
LOCAL_TZ = timezone(timedelta(hours=5))  # UTC+5

def decode_mime_header(value):
    """декодирование заголовка From/Subject/Attachment"""
    parts = decode_header(value)
    decoded = ''
    for part, enc in parts:
        if isinstance(part, bytes):
            decoded += part.decode(enc or 'utf-8', errors='replace')
        else:
            decoded += part
    return decoded

def get_attachments(msg):
    """список вложений с именем и размером"""
    attachments = []
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        filename = part.get_filename()
        if filename:
            size = len(part.get_payload(decode=True) or b'')
            attachments.append({'name': decode_mime_header(filename), 'size': size})
    return attachments

def parse_date_local(date_str):
    """парсинг даты письма с учётом локального часового пояса"""
    try:
        dt = parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(LOCAL_TZ)
    except Exception:
        return parsedate_to_datetime('1 Jan 1970')

@click.command()
@click.option('--ssl', 'use_ssl', is_flag=True, default=False)
@click.option('-s', '--server', required=True)
@click.option('-u', '--user', required=True)
@click.option('-n', nargs=2, type=int, default=(1, 10), help='Последние N писем')
@click.option('-v', '--verbose', is_flag=True, default=False)
@click.option('-a', '--attachments', is_flag=True, default=False, help='Показывать имена и размеры вложений')
def main(use_ssl, server, user, n, verbose, attachments):
    password = getpass.getpass('Пароль: ')
    host, port = (server.rsplit(':', 1) if ':' in server else (server, None))
    port = int(port) if port else (993 if use_ssl else 143)

    if use_ssl:
        mail = imaplib.IMAP4_SSL(host, port)
    else:
        mail = imaplib.IMAP4(host, port)

    mail.login(user, password)
    if verbose:
        print(f'Логин успешен: {user}')

    status, count_bytes = mail.select('INBOX')
    total = int(count_bytes[0])

    n1, n2 = n
    if n2 is None:
        n2 = total

    start = max(total - n2 + 1, 1)
    end   = total - n1 + 1
    seq = f'{start}:{end}'

    typ, data = mail.fetch(seq, '(RFC822)')
    mails = []

    for i in range(0, len(data), 2):
        if len(data[i]) < 2 or data[i] is None:
            continue
        msg = email.message_from_bytes(data[i][1])
        mail_info = {
            'from': decode_mime_header(msg.get('From','')),
            'to': decode_mime_header(msg.get('To','')),
            'subject': decode_mime_header(msg.get('Subject','')),
            'date': msg.get('Date',''),
            'size': len(data[i][1]),
            'attachments': get_attachments(msg)
        }
        mails.append(mail_info)

    mails_sorted = sorted(
        mails,
        key=lambda m: parse_date_local(m['date']),
        reverse=True
    )

    # вывод
    print(f"{'№':>3} {'От кого':30} {'Кому':30} {'Тема':30} {'Дата':25} {'Размер':>7} {'Аттачи':>6}")
    for idx, m in enumerate(mails_sorted, start=1):
        attach_count = len(m['attachments'])
        print(f"{idx:>3} {m['from'][:30]:30} {m['to'][:30]:30} {m['subject'][:30]:30} "
            f"{parse_date_local(m['date']).strftime('%d-%b-%Y %H:%M:%S'):25} "
            f"{m['size']:>7} {attach_count:>6}")

        # если включен -a, то выводим вложения отдельным блоком
        if attachments and attach_count > 0:
            for a in m['attachments']:
                print(f"       -> {a['name']} ({a['size']} байт)")

    mail.logout()

if __name__ == '__main__':
    main()
