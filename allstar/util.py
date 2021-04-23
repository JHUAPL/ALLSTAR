def package_part(pkg):
    if pkg <= 'libapr-dev':
        return 1
    elif pkg <= 'liblingua-stem-perl':
        return 2
    elif pkg <= 'mate-system-tools':
        return 3
    elif pkg <= 'zzuf':
        return 4
    else:
        return None
