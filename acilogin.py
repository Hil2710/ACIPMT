from acipdt import FabLogin


def aci_login():
    # Static ACI info
    aci_usr = 'carl'
    aci_pwd = '32!somuL'
    aci_ip = '10.40.1.24'
    # Initialize acipdt FabLogin method
    aci_login = FabLogin(aci_ip, aci_usr, aci_pwd)
    # Login, retrieve ACI cookie
    aci_cookies = aci_login.login()
    # Return cookie and ACI IP for later use
    return(aci_ip, aci_cookies)
