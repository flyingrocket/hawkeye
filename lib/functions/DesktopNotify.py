#! /usr/bin/env python3

# notifications for the desktop
def desktop_notify(messages):

    print()
    print('Notify desktop...')
    # for message in messages:
        # hyperlink_format = '<a href="{link}">{text}</a>'
        # print(hyperlink_format.format(link='http://foo/bar', text=message))

    # sudo apt install python3-notify2
    import notify2

    try:
        notify2.init(app_name + app_version)
        n = notify2.Notification(app_name.capitalize() + ' ' + app_version + ' FAIL', "\n".join(messages))
        n.show()
    except Exception as e:
        # the first one is usually the message.
        App.fail('Could not notify desktop. Package python3-notify2 installed? {}'.format(e.args[1]))