"""
Retrieve and extract data via HTTP from SEL devices.

The methods of :class:`SELHTTP` fetch pages, and the parsing is done by pure
functions that can be tested without a device:

- Relay pages contain the output of an ASCII command, which is parsed by
  functions that also work for the output of the command over Telnet or
  serial (:mod:`~peat.modules.sel.relay_command_parse` and
  :mod:`~peat.modules.sel.relay_parse`)
- RTAC and SEL-3620 pages are parsed by :mod:`~peat.modules.sel.sel_web_parse`

Authors

- Aidan Kollar
- Amanda Gonzales
- Christopher Goes
- Idaho National Lab
- Jason Hall
- Jessica Robinson
- Ryan Vrecenar
"""

from collections.abc import Callable, Mapping
from pathlib import PurePosixPath
from time import sleep
from typing import Literal
from urllib.parse import urljoin, urlparse

from requests import Response

from peat import DeviceData, PeatError, config, datastore, log, utils
from peat.protocols import HTTP

from .relay_command_parse import (
    merge_show_groups,
    normalize_keys,
    parse_comments,
    parse_eth_output,
    parse_meter_energy,
    parse_meter_values,
    parse_show_groups,
    parse_simple_line,  # noqa: F401 (was defined in this module)
    parse_ver_output,
    process_eth_info,
    process_ver_info,
)
from .relay_parse import (
    get_date_format,
    parse_and_process_events,
    parse_status_output,
    process_info_into_dev,
    process_port_settings,
    split_lines,
)
from .sel_files import (
    SOURCE_COMMAND_OUTPUT,
    SOURCE_WEB_DOWNLOAD,
    SOURCE_WEB_PAGE,
    record_downloaded_file,
    write_and_record_file,
)
from .sel_web_parse import (
    GATEWAY_PAGES,
    clean_text,  # noqa: F401 (was defined in this module)
    derive_relay_session_url,
    extract_login_token,
    extract_pre_text,
    parse_gateway_index,
    parse_gateway_syslog,
    parse_html_table,
    parse_rtac_device_info,
    parse_rtac_diagnostics,
    parse_rtac_files,
    parse_rtac_post_summary,
    parse_soe_csv,
    parse_web_accounts,
    parse_x509_export_links,
    process_gateway_syslog,
    process_rtac_device_info,
    process_rtac_diagnostics,
    process_rtac_files,
    process_rtac_post_summary,
    process_soe_events,
    process_web_accounts,
    read_html,  # noqa: F401 (was defined in this module)
)


class SELHTTP(HTTP):
    """
    HTTP scraper for SEL devices.

    Models supported: 3530 RTAC and 351, 351S and 451 relays.
    """

    def __init__(self, *args, **kwargs) -> None:
        self._rando: str = ""  # "rando" field from 'input' login page element
        self._session_url: str = ""
        self._url_parts: tuple[str, str] | None = None
        self._found_url: bool = False
        self._port_args_len: int | None = None
        self._logic_page_style: str | None = None
        self.successful_creds: tuple[str, str] | None = None
        self.rtac_l1_user: str = "acc"
        self.session_id: str = ""
        self.rtac_logged_in: bool = False
        self.relay_logged_in: bool = False
        self.cookies: dict[str, str] = {}
        self.gateway_l1_user: str = ""
        self.gateway_logged_in: bool = False
        super().__init__(*args, **kwargs)

    @property
    def _rtac_session(self) -> dict[str, str]:
        return {
            "session_id": self.session_id,
            "session_username": self.rtac_l1_user,
        }

    def disconnect(self) -> None:
        if self.rtac_logged_in and self._session:
            self.rtac_log_out()
        super().disconnect()

    def _extract_login_token(self, page: Response, hidden_only: bool = True) -> str | None:
        """
        Token in a login page that's sent with the credentials (the value
        of the hidden ``<input>``), for relays, RTACs, and the SEL-3620.
        Refer to :func:`~peat.modules.sel.sel_web_parse.extract_login_token`.

        Returns:
            The token, or :obj:`None` if the page doesn't have one
        """
        token = extract_login_token(page.content, hidden_only=hidden_only)

        if token is None:
            self.log.debug("Failed to find 'input' field in login page")
            self.log.trace2(f"** Page data **\n{page.content!r}\n")

        return token

    def login(
        self,
        user: str = "ACC",
        passwd: str = "OTTER",
        protocol: Literal["http", "https"] = "http",
    ) -> bool:
        """
        Attempt to login to a relay's HTTP server and get a session.

        If the login succeeds, the credentials are stored in the
        ``successful_creds`` class variable and :obj:`True` is returned.

        The session URL is determined from the response by
        :func:`~peat.modules.sel.sel_web_parse.derive_relay_session_url`.

        .. warning::
           This method is NOT to be used for SEL RTACs.
           Instead, use :meth:`~peat.modules.sel.sel_http.SELHTTP.login_rtac`

        Args:
            user: Username to use for login
            passwd: Password to use for login
            protocol: HTTP protocol to use ('http' or 'https')

        Returns:
            If the login was successful. :obj:`False` if the relay rejected
            the credentials, or the login couldn't be attempted.

        Raises:
            PeatError: The relay didn't reject the credentials, but the session
                can't be determined from the response. This is an exception,
                so callers don't try other credentials (failed logins on the
                relay), e.g. the credential loop in ``SELRelay._verify_http``.
        """
        self.log.debug(f"Attempting login via {protocol}")

        # Get index.html or whatever the root page is
        page = self.get(protocol=protocol, use_cache=True)
        if not page:
            self.log.warning("Login failed: could not get login page")
            return False

        # TODO: if "2AC" is in the login page script, it's probably a 351S
        #   Tested two 451's and neither has it
        token = self._extract_login_token(page, hidden_only=False)
        if token is None:
            return False

        # set protocol now that we know it worked
        self.protocol = protocol

        self._rando = token
        self.log.trace2(f"Rando: {self._rando}")

        # TODO: 351S allows login to level 2
        login_data = {"usrid": user, "pswd": passwd, "rando": self._rando}

        login_url = f"{self.url}/login"
        self.log.trace(f"Sending login POST request to {login_url}")
        resp = self.session.post(url=login_url, data=login_data, timeout=self.timeout)

        if not resp or resp.status_code != 200:
            self.log.error(
                f"Login failed: bad response ({resp.status_code if resp else 'No response'})"
            )
            return False

        self.log.trace(f"Response URL: {resp.url}")

        if "error=invalid" in resp.url:
            self.log.error(f"Login failed: invalid credentials for user '{user}'")
            return False

        sess_url = derive_relay_session_url(resp.url, resp.content, base_url=login_url)
        if not sess_url:
            # The relay didn't reject the credentials, so they're probably valid.
            # Returning False would make callers try other credentials (e.g. the
            # credential loop in SELRelay._verify_http), which are failed logins
            # on the relay that may trigger an alarm or a lockout. So this raises,
            # as the SEL-351 path did before (TypeError when there was no link).
            # The response URL isn't logged here, since it may have the session ID.
            self.relay_logged_in = False
            raise PeatError(
                f"Relay login for user '{user}' was not rejected, but the session URL "
                f"could not be determined from the response (not trying other credentials)"
            )

        self._session_url = sess_url
        self.log.trace(f"Final session URL: {self._session_url}")

        self.successful_creds = user, passwd
        self.relay_logged_in = True

        return True

    def read_page(self, cmd: str, param: str | None = None) -> str:
        """
        Creates URL from given cmd and parameter and extracts text data from that page.

        Args:
            cmd: command string for webpage url
            param: command parameters for webpage url

        Returns:
            The relevant page data needed for parsing

        Raises:
            PeatError: if the page read fails. This may be because PEAT can't
                determine the correct command URL format for the device or
                if another error occurs, such as a communication error.
        """
        if not self._url_parts:
            self.log.trace(
                "'_url_parts' attribute is unset, attempting to determine the proper URL format"
            )

            for parts in [("", ".html"), ("static_command.html?cmd=", "")]:
                try:
                    data = self._get_page(self._gen_url(cmd, parts, param))
                    self._url_parts = parts
                    self._found_url = True
                    self.log.debug(f"Found command URL! Parts: {parts}")
                    return data
                except PeatError:
                    continue

            self._url_parts = None
            raise PeatError(f"could not determine command URL for {self.ip}")

        return self._get_page(self._gen_url(cmd, self._url_parts, param))

    def _get_page(self, url: str) -> str:
        self.log.trace2(f"Getting page: {url}")

        response = self.session.get(url, timeout=self.timeout)

        if response.status_code != 200:
            if self._found_url:
                self.log.debug(
                    f"Code '{response.status_code}' from '{url}'\n\n"
                    f"** Raw response data **\n\n{repr(response.content)}\n"
                )
            raise PeatError(f"session was broken to {self.ip}:{self.port}")

        # Save the raw file to disk as an artifact, and hash it
        try:
            if response.content:
                dev = datastore.get(self.ip)

                # Replace the web session ID in the path with a placeholder,
                # so it isn't in recorded file paths (e.g. device-data-files.jsonl)
                f_name = "/".join(url.split("/")[3:])
                if self._session_url and url.startswith(self._session_url):
                    f_name = f"protected/session/{self._page_name(url)}"
                f_name = f_name.replace("?", "_").replace(":", "_")

                # Ensure the written file ends with ".html"
                # e.g. turn "...static_command.html_cmd=ver"
                # into "...static_command_cmd=ver.html"
                if ".html" in f_name and not f_name.endswith(".html"):
                    f_name = f_name.replace(".html", "")
                    f_name = f"{f_name}.html"

                write_and_record_file(
                    dev=dev,
                    data=response.content,
                    filename=f"http_files/{f_name}",
                    transport=self.protocol or "http",
                    source=SOURCE_WEB_PAGE,
                    peat_module="SELRelay",
                    description="Page from the relay's web interface",
                    extra={"page": self._page_name(url)},
                )
        except Exception:
            self.log.exception(f"Failed to write page '{url}' to file")

        data = self.parse_page_data(response.content)
        if config.DEBUG >= 4:
            self.log.trace4(f"Data for '{url}': {repr(data)}")

        return data

    def _page_name(self, url: str) -> str:
        """
        The page and parameters in a relay URL, without the session ID
        that's part of the path (e.g. ``static_command.html?cmd=ver``).
        """
        if self._session_url and url.startswith(self._session_url):
            return url[len(self._session_url) :]

        parts = urlparse(url)
        return f"{parts.path}?{parts.query}" if parts.query else parts.path

    def _gen_url(self, cmd: str, parts: tuple[str, str], param: str | None) -> str:
        url = f"{self._session_url}{parts[0]}{cmd}{parts[1]}"
        if param:
            url += f"&param={param}"
        return url

    def parse_page_data(self, content: bytes) -> str:
        """
        Parse raw HTML page data and extract the contents of the ``pre`` section.

        The "pre" tag contains raw text. For the SEL relays, this usually
        contains the output of the command run "under the hood", e.g. "sho p1".
        Refer to :func:`~peat.modules.sel.sel_web_parse.extract_pre_text`.

        Raises:
            PeatError: if the page doesn't have a ``pre`` section
        """
        try:
            return extract_pre_text(content)
        except ValueError:
            raise PeatError("Failed to find 'pre' section in page content") from None

    # -------------------- RTAC Web Pages --------------------

    def login_rtac(
        self,
        user: str = "ACC",
        passwd: str = "OTTER",
        protocol: Literal["http", "https"] = "https",
    ) -> bool:
        """
        Login to the HTTP interface for the SEL RTAC.
        This works for 3530, 3530-4, and 3350.

        Note: Nginx is the web server used by the SEL RTAC devices.
        """
        page = self.get("", protocol)
        if not page:
            self.log.warning("Login failed, could not get login page")
            return False

        # NOTE: SEL RTAC does not contain Device ID on front page
        token = self._extract_login_token(page)
        if token is None:
            return False
        self._rando = token

        # set protocol now that we know it worked
        self.protocol = protocol

        login_data = {
            "session_username": user,
            "password": passwd,
            "temp_auth_token": self._rando,
        }
        resp = self.post(f"{self.url}/auth.sel?{querystr()}", params=login_data)
        if not resp or resp.status_code != 200:
            return False

        # 200 can also tell us bad password, check for response,
        # "Failure to login invalid user/pass"
        if "Failure" in resp.text:
            return False

        self.rtac_l1_user = user
        self.session_id = resp.text  # resp.content
        self.rtac_logged_in = True
        self.log.info("Logged in to RTAC")

        return True

    def _post_rtac(self, page: str, dev: DeviceData, query: bool = False) -> Response | None:
        """
        ``POST`` a page of the RTAC web interface with the session parameters,
        e.g. ``device_info.sel``. If ``query`` is set, a timestamp is added
        to the URL (as the RTAC web interface does for some pages).
        """
        url = f"{self.url}/{page}"
        if query:
            url = f"{url}?{querystr()}"

        return self.post(url, params=self._rtac_session, dev=dev)

    @staticmethod
    def dump_htmltable(html_page: Response | None, results: dict) -> None:
        """
        Read the first table in a page into ``results``, with
        :func:`~peat.modules.sel.sel_web_parse.parse_html_table`.
        Nothing is added if there isn't a page or a table.
        """
        # TODO: return dict instead of updating a passed variable
        if html_page is not None:
            results.update(parse_html_table(html_page.content))

    def get_index(self, dev: DeviceData) -> dict:
        """
        Get the data from the gateway dashboard (``index.sel``).
        Refer to :func:`~peat.modules.sel.sel_web_parse.parse_gateway_index`.
        """
        self.log.info("Getting Gateway index info")

        # NOTE: the cookie dict is also sent as query parameters, as it always
        # has been. It's unknown if the gateway needs them, so this is kept
        # until it can be tested on a device.
        device_info = self.get(page="index.sel", protocol="https", params=self.cookies, dev=dev)

        return {
            "web_device_info": parse_gateway_index(device_info.content if device_info else None)
        }

    def view_dashboard(self, dev: DeviceData) -> dict:
        """
        Get the data from the RTAC 'dashboard': device information
        (``device_info.sel``), diagnostics (``diagnostics.sel``, or
        ``diag_report.sel`` if that fails), and the power-on self test
        summary (``post_summary.sel``).
        """
        dash_config = {
            "web_device_info": {},
            "web_diagnostics": {},
            "web_post_summary": {},
        }

        # === Device Info ===
        self.log.info("Getting RTAC device info (device_info.sel)")
        dev_info_response = self._post_rtac("device_info.sel", dev, query=True)

        if not dev_info_response or not dev_info_response.content:
            self.log.error("No RTAC device info data (device_info.sel)")
        else:
            web_inf = parse_rtac_device_info(dev_info_response.content)
            if not web_inf:
                self.log.warning("No table in 'device_info' (check credentials?)")
            dash_config["web_device_info"] = web_inf
            dev.extra["web_device_info"] = web_inf
            # This was previously inside SELRTAC._verify_http()
            process_rtac_device_info(web_inf, dev)

        # === Diagnostics ===
        self.log.debug("Getting RTAC diagnostics data (diagnostics.sel)")
        diag_response = self._post_rtac("diagnostics.sel", dev, query=True)

        if not diag_response or not diag_response.content:
            self.log.warning("No results from 'diagnostics.sel', attempting 'diag_report.sel'")
            diag_response = self._post_rtac("diag_report.sel", dev)

        if not diag_response or not diag_response.content:
            self.log.warning("No RTAC diagnostics data (diagnostics.sel or diag_report.sel)")
        else:
            web_diag = parse_rtac_diagnostics(diag_response.content)
            if not web_diag:
                self.log.warning("No table in 'diagnostics' (check credentials?)")
            web_diag = process_rtac_diagnostics(web_diag, dev)
            dash_config["web_diagnostics"] = web_diag
            dev.extra["web_diagnostics"] = web_diag

        # === Post summary ===
        self.log.info("Getting RTAC post summary data (post_summary.sel)")
        post_summary = self._post_rtac("post_summary.sel", dev, query=True)

        if not post_summary or not post_summary.content:
            self.log.error("No RTAC post summary data (post_summary.sel)")
        else:
            # TODO: cleanup the default keys and values for the dicts from various pages
            #   remove ':', lowercase underscore_separated, bools
            # TODO: dump parsed intermediate representations to JSON files
            summary = parse_rtac_post_summary(post_summary.content)
            if not summary:
                self.log.debug("No table in 'post_summary' (check credentials?)")
            dash_config["web_post_summary"] = summary
            dev.extra["web_post_summary"] = summary
            process_rtac_post_summary(summary, dev)

        return dash_config

    def view_usagepolicy(self, dev: DeviceData) -> dict:
        """
        Get the data from the RTAC 'usagepolicy' (``customize.sel``).
        """
        self.log.info("Getting RTAC usage policy (customize.sel)")

        web_usagepolicy = {}
        self.dump_htmltable(self._post_rtac("customize.sel", dev), web_usagepolicy)
        dev.extra["web_usagepolicy"] = web_usagepolicy

        return {"web_usagepolicy": web_usagepolicy}

    def view_filesondevice(self, dev: DeviceData) -> dict:
        """
        Get data about files on a RTAC (``file_repository.sel``).
        Refer to :func:`~peat.modules.sel.sel_web_parse.parse_rtac_files`.
        """
        self.log.info("Getting RTAC file listing (file_repository.sel)")

        # Note: we can potentially upload files via this interface using
        # upload_file.sel (params from data + contents)

        files_repo = self._post_rtac("file_repository.sel", dev)

        web_files = parse_rtac_files(files_repo.content if files_repo else None)
        process_rtac_files(web_files, dev)

        return {"web_files": web_files}

    def download_http_files(self, dev: DeviceData) -> dict:
        """
        Take file listing from view_filesondevice() and download from web server
        """
        # just a dict to indicate a file was downloaded from the device
        downloaded_files = {}
        if not dev.extra.get("web_files"):
            self.log.error(
                "PEAT did not find any web files listed on the device, skipping file download..."
            )
            return downloaded_files

        num_downloads = len(dev.extra["web_files"])
        self.log.info(f"Attempting to download {num_downloads} file(s)...")

        # For each file in web_files, send a request to download the file to local machine
        for file in dev.extra["web_files"]:
            filename = str(file)
            self.log.info(f"Attempting to download file via http: {file}")

            payload = {
                "header": "{'User-Agent': 'Mozilla/5.0'}",
                "vfsid": "file_manager",
                "filename": filename,
                **self._rtac_session,
            }

            try:
                dl_repo = self.post(f"{self.url}/download.sel", params=payload, dev=dev)
                dev.write_file(dl_repo.content, filename)
                downloaded_files[filename] = "success"
            except AttributeError as err:
                # Attribute error is likely caused by file not being found
                self.log.error(
                    f"Error trying to download {filename} (possible incorrect filename?): {err}"
                )
                downloaded_files[filename] = "failure"

        return downloaded_files

    # TODO: view_features parsing is not extracting anything on PEAT rack rtac
    def view_features(self, dev: DeviceData) -> dict:
        """
        Get data about features on a RTAC (``licensed_features.sel``).
        """
        self.log.info("Getting RTAC features list (licensed_features.sel)")

        web_features = {}
        self.dump_htmltable(self._post_rtac("licensed_features.sel", dev), web_features)

        dev.extra["web_features"] = web_features
        return {"web_features": web_features}

    def _process_accounts_page(self, page: Response | None, dev: DeviceData) -> dict:
        """
        Parse and process a page with the table of user accounts, which is
        the same on the RTAC (``user_table.sel``) and SEL-3620 (``Users.sel``).
        Refer to :func:`~peat.modules.sel.sel_web_parse.parse_web_accounts`.
        """
        web_accounts, usernames = parse_web_accounts(page.content if page else None)
        process_web_accounts(web_accounts, usernames, dev)

        return {"web_accounts": web_accounts}

    def view_accounts(self, dev: DeviceData) -> dict:
        """
        Get data about user accounts on a RTAC (``user_table.sel``).
        """

        # NOTE
        #   Users can be added and passwords can be changed via this interface
        #   Add user with "add_user.sel" then "add_user_save.sel"
        #     Param(account_expiration, passwd, confirm_password, complex_password,
        #           submit=Submit, auto_login, status, user_id, submit,
        #           membership_list, description, close=Close)
        #   Change password with "change_password.sel" then "password_save.sel"
        #     Param(new_password, old_password, confirm_password)

        self.log.info("Getting RTAC user accounts (user_table.sel)")

        return self._process_accounts_page(self._post_rtac("user_table.sel", dev), dev)

    def view_user_roles(self, dev: DeviceData) -> dict:
        """
        Get data about user roles on a RTAC (``list_user_roles.sel``).
        """
        # New user roles can be added
        # add_new_user_defined_role_template.sel -> add_user_role.sel
        #   Params(role_name, role_desc, membership_list, perm_list)
        self.log.info("Getting RTAC user roles (list_user_roles.sel)")

        web_user_roles = {}
        self.dump_htmltable(self._post_rtac("list_user_roles.sel", dev), web_user_roles)
        for role in web_user_roles.keys():
            dev.related.roles.add(role.strip())

        dev.extra["web_user_roles"] = web_user_roles
        return {"web_user_roles": web_user_roles}

    def view_syslog(self, dev: DeviceData) -> dict:
        """
        Get the system log (SOE, Sequence of Events) from a RTAC (``soe.csv``).

        The log is parsed by :func:`~peat.modules.sel.sel_web_parse.parse_soe_csv`
        and :func:`~peat.modules.sel.sel_web_parse.process_soe_events`.
        """
        self.log.info("Getting RTAC system log data (soe.csv)")

        response = self.session.get(
            f"{self.url}/soe.csv",
            params=self._rtac_session,
            timeout=self.timeout + 10.0,
        )

        if not response or not response.text:
            self.log.error("No response or data for Sequence of Events (SOE) log (soe.csv)")
            return {}

        write_and_record_file(
            dev=dev,
            data=response.content,
            filename="http_files/soe.csv",
            device_path="/soe.csv",
            transport=self.protocol or "http",
            source=SOURCE_WEB_DOWNLOAD,
            peat_module="SELRTAC",
            description="RTAC Sequence of Events (SOE) log",
        )

        # TODO: support parsing of SOE log file directly with SELRTAC.parse()
        records = parse_soe_csv(response.text)
        process_soe_events(records, dev)

        web_syslog_events = [record.fields for record in records]
        dev.write_file(web_syslog_events, "raw-web-syslog-events.json")

        return {"web_syslog_events": web_syslog_events}

    def view_ip_tables(self, dev: DeviceData) -> dict:
        """
        View diagnostics and network data from a RTAC (``services_rpt.cev``).

        Data includes: network state, firewall, route table,
            exeguard, prp diagnostic, arp table.
        """
        self.log.info("Getting RTAC network info (services_rpt.cev)")
        ip_settings = self._post_rtac("services_rpt.cev", dev)

        if not ip_settings or not ip_settings.text:
            self.log.warning("No content returned for services_rpt.cev (web_ip_settings)")
            return {"web_ip_settings": {}}

        # TODO: finish implementing
        # TODO: dev.related.ip.add(...)
        web_ip_settings = {}
        self.log.debug(f"ip_settings content: {ip_settings.text}")

        dev.extra["web_ip_settings"] = web_ip_settings
        return {"web_ip_settings": web_ip_settings}

    def view_ldap(self, dev: DeviceData) -> dict:
        """
        Get LDAP data from a RTAC (``ldap_server_table.sel``,
        ``ldap_settings_table.sel``, ``ldap_group_mapping_table.sel``,
        and ``ldap_attribute_mapping_table.sel``).
        """
        # NOTE: upload with "upload_file.sel" (params form data+contents)
        web_ldap = {
            "servers": {},
            "ldap_setting": {},
            "ldap_group_mapping": {},
            "ldap_attribute_mapping": {},
        }

        self.log.info("Getting RTAC LDAP data")

        for page, key, extra_key in [
            # TODO: dev.related.user.add(...)
            ("ldap_server_table.sel", "servers", "web_ldap_accounts"),
            ("ldap_settings_table.sel", "ldap_setting", "web_ldap_setting"),
            ("ldap_group_mapping_table.sel", "ldap_group_mapping", "web_ldap_grpmapping"),
            ("ldap_attribute_mapping_table.sel", "ldap_attribute_mapping", "web_ldap_attmapping"),
        ]:
            self.dump_htmltable(self._post_rtac(page, dev), web_ldap[key])
            dev.extra[extra_key] = web_ldap[key]

        return {"web_ldap": web_ldap}

    # -------------------- RTAC COMMANDS --------------------

    def rtac_delete_logs(self) -> None:
        """
        Clear log data from a RTAC (``system_restore.sel``).
        """
        self.log.warning("Deleting logs from RTAC")
        session_data = {
            "restore": "false",
            "complete": "true",
            **self._rtac_session,
        }
        self.post(f"{self.url}/system_restore.sel", params=session_data)

    def rtac_log_out(self) -> None:
        """
        Log out of the RTAC (``logout.sel``).
        """
        if self.rtac_logged_in:
            self.log.info("Logging out from RTAC")
            session_data = {
                "action": "logoff",
                **self._rtac_session,
            }
            self.post(f"{self.url}/logout.sel", params=session_data)
            self.rtac_logged_in = False

    def rtac_reboot(self) -> None:
        """
        Restart RTAC (``reboot_device.cev``).
        """
        self.log.info("Rebooting RTAC")
        self.post(f"{self.url}/reboot_device.cev", params=self._rtac_session)
        self.rtac_logged_in = False

    # -------------------- Relay Web pages --------------------

    # The pages contain the output of ASCII commands, which is parsed by
    # functions that also work for the output of the commands over Telnet
    # or serial (relay_command_parse and relay_parse).

    # NOTE: get_device_features() needs to be called before other methods for
    #   some reason, need to get to the bottom of why this is.

    def get_device_features(self, dev: DeviceData) -> bool:
        """
        Get basic information about a relay.

        ``ver`` command page, parsed by
        :func:`~peat.modules.sel.relay_command_parse.parse_ver_output`.

        Data

        - Device model
        - FID
        - BFID
        - CID
        - Checksum (boot firmware)
        - Firmware info
        - Part number
        - Serial number
        - Various additional information about capabilities and boards
        """
        try:
            page = self.read_page("ver")
        except Exception as ex:
            self.log.warning(f"Failed to read device features page: {ex}")
            return False

        process_ver_info(parse_ver_output(page), dev)

        return True

    def get_status(self, dev: DeviceData) -> bool:
        """
        Get device status information from a relay.

        Returns:
            Data extracted from the status page.
            Refer to :func:`~peat.modules.sel.relay_parse.parse_status_output`
            for details on the data extracted from this page.
        """
        try:
            page = self.read_page("sta")
        except Exception as ex:
            self.log.warning(f"Failed to get status page: {ex}")
            return False
        return self._process_status_data(split_lines(page), dev)

    def get_communications(self, dev: DeviceData) -> bool:
        """
        Get communication interface status and current state from a relay.

        ``eth`` command page, parsed by
        :func:`~peat.modules.sel.relay_command_parse.parse_eth_output`.

        NOTE: this is not available on 351S or 351.
        """
        try:
            page = self.read_page("eth")
        except Exception:
            self.log.warning("Failed to get communications page ('eth')")
            return False

        # TODO: add data to the appropriate Interface in data model
        process_eth_info(parse_eth_output(page), dev)

        return True

    def get_port_settings(self, dev: DeviceData) -> bool:
        """
        Get communication port settings from a relay.

        The ``sho`` pages are parsed by
        :func:`~peat.modules.sel.relay_command_parse.parse_show_groups`.
        ``dev.extra["interfaces"]`` has the settings of each port, grouped
        by heading on relays that group them (e.g. the 451).
        """
        # Simple device model-agnostic check to determine the proper URL format
        p1_page = ""  # Cache the page from our silly check
        if not self._port_args_len:
            fallback = None

            # %20 = space character (" "). So, "sho" with "P 1" as parameter for 451.
            for args in [("shop1",), ("sho", "P%201")]:
                try:
                    page = self.read_page(*args)
                except Exception:
                    continue

                # The relay may return a page for a command it doesn't know.
                # Try the other format, and use this one if that fails too.
                if "Invalid Command" in page:
                    if fallback is None:
                        fallback = (len(args), page)
                    continue

                self._port_args_len = len(args)
                p1_page = page
                break

            if not self._port_args_len and fallback:
                self._port_args_len, p1_page = fallback

        if not self._port_args_len:
            self.log.warning("Unable to find a valid port settings page")
            return False

        port_results = {}
        for index in range(1, 6):
            # "Port F" is sometimes referred to as port 4 in the relay...
            if index == 4:
                port_id = "F"
            else:
                port_id = str(index)
            port_name = f"Port {port_id}"

            if index == 1 and p1_page:
                page = p1_page
            else:
                try:
                    if self._port_args_len == 1:  # 351, 351S
                        # Port F is retrieved as port 4 on older devices
                        page = self.read_page(f"shop{str(4) if index == 4 else port_id}")
                    else:  # 451
                        page = self.read_page("sho", f"P%20{port_id}")
                except Exception as ex:
                    self.log.warning(f"Failed to get {port_name} page: {ex}")
                    continue

            if "Invalid Command" in page:
                self.log.debug(f"Device doesn't have {port_name} ('Invalid Command')")
                port_results[port_name] = {}
                continue

            groups = parse_show_groups(page)
            settings = merge_show_groups(groups)

            # SEL 351, 351S, 311L: settings aren't grouped.
            # SEL 451: settings are grouped by heading, e.g. "Protocol Selection".
            port_results[port_name] = settings if self._port_args_len == 1 else groups

            process_port_settings(port_id, settings, dev)

        dev.extra["interfaces"] = port_results
        return True

    def get_front_panel_settings(self, dev: DeviceData) -> bool:
        """
        Get front panel settings from a relay.

        ``dev.extra["front_panel_data"]`` has the settings grouped by heading
        (e.g. ``front_panel_settings``), with comments split from the values
        of ``front_panel_settings``.
        """
        try:
            page = self.read_page("sho", "F")
        except Exception as ex:
            self.log.warning(f"Failed to get front panel settings page: {ex}")
            return False

        settings = normalize_keys(parse_show_groups(page))
        if "front_panel_settings" in settings:
            settings["front_panel_settings"] = parse_comments(settings["front_panel_settings"])
        else:
            self.log.debug("No 'Front Panel Settings' heading in the front panel settings page")

        dev.extra["front_panel_data"] = settings
        return True

    def get_sequential_events(self, dev: DeviceData) -> bool:
        """
        Get Sequential Event Recorder (SER) log data from a relay.

        This method has been tested against SEL 351, 351S, and 451 relays.
        """
        try:
            page = self.read_page("ser")
        except Exception as ex:
            self.log.warning(f"Failed to read SER page: {ex}")
            return False

        try:
            parse_and_process_events(page, "Sequential Event Recorder ('ser')", dev)
        except Exception:
            self.log.exception(f"Failed parsing of SER data from {dev.ip}")
            return False

        return True

    def get_historical_events(self, dev: DeviceData) -> bool:
        """
        Get historical event log from a relay.

        Tested on SEL 351S and 451 relays. May work on the 351.

        The page is parsed with
        :func:`~peat.modules.sel.relay_parse.parse_and_process_events`, the same
        parser used for ``HISTORY.TXT`` and the ``his`` command, including the
        status information before the events (even if there are no events).

        .. warning::
           Older versions of the 351 may not support this (failed on a device
           with copyright year 2009, your mileage may vary on newer devices).
        """
        try:
            page = self.read_page("his")
        except Exception as ex:
            self.log.warning(f"Failed to read historical events page: {ex}")
            return False

        events, _ = parse_and_process_events(page, "Historical Events ('his')", dev)

        if not events:
            self.log.debug("No historical events available")
            return False

        return True

    def get_meter_automation(self, dev: DeviceData) -> bool:
        """
        Get meter automation data from a relay.

        Values: :class:`dict` of ``{"AMV<int>": <float>}``
        """
        try:
            page = self.read_page("met", "AMV")
        except Exception as ex:
            self.log.warning(f"Failed to get meter automation page: {ex}")
            return False

        dev.extra["meter_automation"] = parse_meter_values(page, "AMV")
        return True

    def get_meter_protection(self, dev: DeviceData) -> bool:
        """
        Get meter protection data from a relay.

        Values: :class:`dict` of ``{"PMV<int>": <float>}``
        """
        try:
            page = self.read_page("met", "PMV")
        except Exception as ex:
            self.log.warning(f"Failed to get meter protection page: {ex}")
            return False

        dev.extra["meter_protection"] = parse_meter_values(page, "PMV")
        return True

    def get_meter_energy(self, dev: DeviceData) -> bool:
        """
        Get meter energy data from a relay.
        Refer to :func:`~peat.modules.sel.relay_command_parse.parse_meter_energy`.
        """
        # TODO: more flexible way to check this instead of the model
        args = ["met", "E"] if "451" in dev.description.model else ["mete"]
        try:
            page = self.read_page(*args)
        except Exception as ex:
            self.log.warning(f"Failed to get meter energy page: {ex}")
            return False

        dev.extra["meter_energy"] = parse_meter_energy(page, get_date_format(dev))
        return True

    def get_output_data(self, dev: DeviceData) -> bool:
        """
        Get output data (main_board, etc.) from a relay.

        NOTE: this doesn't work on SEL-351 or 351S (or possibly just older software).
        """
        try:
            page = self.read_page("sho", "O")
        except Exception as ex:
            self.log.warning(f"Failed to get output data page: {ex}")
            return False

        results = normalize_keys(parse_show_groups(page))
        if "main_board" in results:
            results["main_board"] = parse_comments(results["main_board"])

        dev.extra["output_data"] = results
        return True

    # NOTE: this isn't called by SELRelay.pull_http() at the moment
    def get_logic_data(self, dev: DeviceData) -> bool:
        """
        Get logic settings and control equations from a relay.

        This is the output of the "sho l" command, e.g. "sho l",
        "sho l 1" (logic group 1), etc.
        "sho l" (no argument) shows the logic for the "active" logic group.

        There should be 6 logic groups. Other relays may have more or less.

        This should work on 351S.

        The 451 calls this "Protection", and structure is far more complicated.

        The settings are parsed by
        :func:`~peat.modules.sel.relay_command_parse.parse_show_groups`
        (``=`` and ``:=`` styles, with equations continued on the next line).
        If a page has no settings, the page is kept as-is.
        """

        # 351S: "shol1.html", "shol2.html", etc.
        # 351: "sho1.html" which shows "SHO 1" and "SHO L 1"
        #   in two separate sections in the returned page.
        # TODO: implement SEL-451 Group and Protection logic parsing.

        # Simple device model-agnostic check to determine the proper URL format
        l1_page = ""  # Cache the page from our silly check
        if not self._logic_page_style:
            # %20 = space character (" "). So, "sho" with "P 1" as parameter for 451.
            for style, args in {
                "351S": ("shol",),
                "351": ("sho1",),  # the number 1, not a 'l'
                "451": ("sho", "L%201"),
            }.items():
                try:
                    l1_page = self.read_page(*args)
                except Exception:
                    continue
                else:
                    self._logic_page_style = style
                    break

        if not self._logic_page_style:
            self.log.warning("Unable to find a valid logic settings page")
            return False

        logic_results = {}
        for index in range(1, 7):  # 1-6
            sleep(0.2)

            if index == 1 and l1_page:
                page = l1_page
            else:
                try:
                    if self._logic_page_style == "351S":
                        page = self.read_page(f"shol{index}")
                    elif self._logic_page_style == "351":
                        page = self.read_page(f"sho{index}")
                    else:  # 451
                        page = self.read_page("sho", f"L%20{index}")
                except Exception as ex:
                    self.log.warning(f"Failed to get logic group {index} page: {ex}")
                    continue

            page = page.strip()
            raw_group_str = f"raw_logic_group_{index}"
            group_str = f"group_{index}"

            write_and_record_file(
                dev=dev,
                data=page,
                filename=f"http_commands/{raw_group_str}.txt",
                transport=self.protocol or "http",
                source=SOURCE_COMMAND_OUTPUT,
                peat_module="SELRelay",
                description=f"Logic group {index} settings from the relay's web interface",
            )

            if "invalid command" in page.lower():
                self.log.debug(f"Device doesn't have logic group {index} ('Invalid Command')")
                logic_results[group_str] = {}
                continue

            raw_settings = merge_show_groups(parse_show_groups(page))
            if raw_settings:
                logic_results[group_str] = raw_settings
            else:
                self.log.warning(f"No settings in logic group {index} page, keeping it as-is")
                logic_results[raw_group_str] = page

        dev.extra["control_equations"] = logic_results
        return True

    def _process_status_data(self, lines: list[str], dev: DeviceData) -> bool:
        try:
            info = parse_status_output(lines)
            if not info:
                self.log.warning(f"Failed to parse status info\nRaw lines: {lines}")
                return False
            process_info_into_dev(info, dev)
        except Exception:
            log.exception("Failed to parse status data")
            return False
        return True

    # -------------------- Gateway Web pages --------------------

    def login_3620(
        self,
        user: str = "admin",
        passwd: str = "Admin123!",
    ) -> bool:
        """
        Login to the HTTPS web interface for the SEL-3620 Gateway.
        """
        page = self.get("", protocol="https")
        if not page:
            self.log.warning("Login failed: could not retrieve login page.")
            return False

        token = self._extract_login_token(page)
        if token is None:
            return False

        self._rando = token
        SELSESSID = self._rando
        self.protocol = "https"  # Set protocol after confirming it worked

        login_data = {
            "Username": user,
            "Password": passwd,
            "submit": "Submit",
            "SELSESSID": SELSESSID,
        }

        self.cookies = {
            "Cookie": f"SELSESSID={SELSESSID}",
        }
        url = urljoin(self.url, "Login.sel")
        resp = self.post(url, data=login_data)
        if not resp or resp.status_code != 200:
            self.log.warning("Login failed: received non-200 response.")
            return False

        if "ERROR MESSAGES" in resp.text:
            return False

        self.gateway_l1_user = user
        self.session_id = resp.text
        self.gateway_logged_in = True
        self.log.info("Logged in to Gateway!")
        return True

    # TODO: generate backup
    #   FileManagement.sel#backupFileTab

    def _pull_gateway_page(self, dev: DeviceData, name: str) -> dict:
        """
        Read a page of the SEL-3620 that isn't parsed yet, from
        :data:`~peat.modules.sel.sel_web_parse.GATEWAY_PAGES`.

        The page is saved (by :meth:`~peat.protocols.http.HTTP.post`), and
        an empty :class:`dict` is put in ``dev.extra``.

        .. note::
           The name of this method must not start with ``gateway_``, since
           :meth:`~peat.modules.sel.sel_3620.SEL3620._pull` calls every method
           of this class whose name starts with ``gateway_``.

        Returns:
            ``{<result key>: {}}``, or an empty :class:`dict` if the page
            couldn't be read
        """
        page = GATEWAY_PAGES[name]
        self.log.info(f"Getting {page.description} ({page.page})...")
        url = urljoin(self.url, page.page)

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()  # Raise an error for bad responses
        except Exception as ex:
            self.log.warning(f"Failed to read {page.description} page ({page.page}): {ex}")
            return {}

        if page.require_content and not response.content:
            self.log.warning(f"Failed to read {page.description} page ({page.page}): no data")
            return {}

        # TODO: parse the page and put the data into the data model.
        #   The pages likely have tables, which parse_html_table() can read.
        data = {}

        dev.extra[page.extra_key] = data
        return {page.result_key: data}

    def gateway_accounts(self, dev: DeviceData) -> dict:
        """
        Get user accounts from gateway (``Users.sel``).
        """

        self.log.info("Getting gateway user accounts")
        url = urljoin(self.url, "Users.sel")
        accounts_page = self.post(url, data=self._rando, dev=dev)

        return self._process_accounts_page(accounts_page, dev)

    def gateway_ldap(self, dev: DeviceData) -> dict:
        """
        Get LDAP settings (``LDAP.sel``).
        """
        return self._pull_gateway_page(dev, "ldap")

    def gateway_radius(self, dev: DeviceData) -> dict:
        """
        Get RADIUS settings (``RADIUS.sel``).
        """
        return self._pull_gateway_page(dev, "radius")

    def gateway_local_groups(self, dev: DeviceData) -> dict:
        """
        Get local groups (``LocalGroups.sel``).
        """
        return self._pull_gateway_page(dev, "local_groups")

    def gateway_network_settings(self, dev: DeviceData) -> dict:
        """
        Get network settings (``NetworkSettings.sel``).
        """
        return self._pull_gateway_page(dev, "network_settings")

    def gateway_static_routes(self, dev: DeviceData) -> dict:
        """
        Get static route configuration (``StaticRoutes.sel``).
        """
        return self._pull_gateway_page(dev, "static_routes")

    def gateway_firewall(self, dev: DeviceData) -> dict:
        """
        Get firewall settings (``Firewall.sel``).
        """
        return self._pull_gateway_page(dev, "firewall")

    def gateway_nat(self, dev: DeviceData) -> dict:
        """
        Get NAT settings (``NAT.sel``).
        """
        return self._pull_gateway_page(dev, "nat")

    def gateway_hosts(self, dev: DeviceData) -> dict:
        """
        Get host configuration (``Hosts.sel``).
        """
        return self._pull_gateway_page(dev, "hosts")

    def gateway_snmp(self, dev: DeviceData) -> dict:
        """
        Get SNMP settings (``SNMP.sel``).
        """
        return self._pull_gateway_page(dev, "snmp")

    def gateway_port_settings(self, dev: DeviceData) -> dict:
        """
        Get serial port settings (``SerialPortSettings.sel``).
        """
        return self._pull_gateway_page(dev, "port_settings")

    def gateway_port_profiles(self, dev: DeviceData) -> dict:
        """
        Get serial port profiles (``SerialPortProfiles.sel``).
        """
        return self._pull_gateway_page(dev, "port_profiles")

    def gateway_port_mappings(self, dev: DeviceData) -> dict:
        """
        Get port mappings (``PortMappings.sel``).
        """
        return self._pull_gateway_page(dev, "port_mappings")

    def gateway_ipsec(self, dev: DeviceData) -> dict:
        """
        Get IPSec connections (``IPsec.sel``).
        """
        return self._pull_gateway_page(dev, "ipsec")

    def gateway_macsec(self, dev: DeviceData) -> dict:
        """
        Get MACSec connections (``MACsec.sel``).
        """
        return self._pull_gateway_page(dev, "macsec")

    def gateway_allowed_clients(self, dev: DeviceData) -> dict:
        """
        Get Allowed Clients (``AllowedClients.sel``).
        """
        return self._pull_gateway_page(dev, "allowed_clients")

    def gateway_sshkey(self, dev: DeviceData) -> dict:
        """
        Get SSH Host Keys (``SSH_Host_Key.sel``).
        """
        return self._pull_gateway_page(dev, "sshkey")

    def gateway_password_management(self, dev: DeviceData) -> dict:
        """
        Get password management messages (``PasswordManagement.sel``).
        """
        return self._pull_gateway_page(dev, "password_management")

    def gateway_system_logs(self, dev: DeviceData) -> dict:
        """
        Get system logs (``SysLogReport.sel``).
        Refer to :func:`~peat.modules.sel.sel_web_parse.parse_gateway_syslog`.
        """
        self.log.info("Getting gateway system logs...")
        url = urljoin(self.url, "SysLogReport.sel")

        try:
            response = self.post(url, data=self._rando, dev=dev)
            response.raise_for_status()
        except Exception as ex:
            self.log.warning(f"Failed to read system logs page: {ex}")
            return {}

        raw_logs = parse_gateway_syslog(response.content)
        process_gateway_syslog(raw_logs, dev)

        dev.write_file(raw_logs, "gateway-system-logs.json")

        return {"gateway_system_logs": raw_logs}

    def gateway_diagnostics(self, dev: DeviceData) -> dict:
        """
        Get diagnostic data from SEL gateway (``Diagnostics.sel``).
        """
        return self._pull_gateway_page(dev, "diagnostics")

    def gateway_proxy_reports(self, dev: DeviceData) -> dict:
        """
        Get proxy reports from ``ProxyReports.sel``.
        """
        # TODO: generate and download reports
        # commands and devices
        # password updates
        # Managed Device Passwords
        # Password Change Log
        return self._pull_gateway_page(dev, "proxy_reports")

    def _is_device_url(self, url: str) -> bool:
        """
        If a URL is a HTTP(S) URL for this device, so a link in a page
        doesn't send the session to another host.
        """
        parts = urlparse(url)
        return (
            parts.scheme in ("http", "https")
            and (parts.hostname or "").lower() == str(self.ip).lower()
        )

    def gateway_cert_export(self, dev: DeviceData) -> dict:
        """
        Export X509 certificates from the gateway (``X509.sel``).

        Each certificate linked by an ``Export`` button is downloaded.
        Relative and absolute links work. Links to other hosts are skipped.
        """
        self.log.info("Downloading X509 certificates from gateway...")
        url = urljoin(self.url, "X509.sel")

        response = self.post(url, data=self._rando, dev=dev, use_cache=True)
        if not response:
            self.log.warning("Failed to read X509 certificates page (X509.sel)")
            return {}

        # Grab the export pages containing all X509 certs listed on the X509 main page
        x509_cert_export = {}
        for href in parse_x509_export_links(response.content):
            # The links may be absolute ("https://<gateway>/...") or relative
            cert_url = urljoin(self.url, href)
            if not self._is_device_url(cert_url):
                self.log.warning(f"Skipping certificate link that isn't on the gateway: {href!r}")
                continue

            # A 5-second timeout sometimes fails, device can be slow
            response = self.post(cert_url, data=self._rando, dev=dev, timeout=17.0)

            if not response or response.status_code != 200:
                self.log.warning(f"Failed to download certificate from {cert_url}")
                continue

            # Hash the exported file. HTTP.post() saved it to "http_files/".
            file_path = getattr(response, "file_path", None)
            try:
                record_downloaded_file(
                    dev=dev,
                    data=response.content,
                    name=file_path.name
                    if file_path
                    else PurePosixPath(urlparse(cert_url).path).name,
                    local_path=file_path,
                    transport=self.protocol or "https",
                    source=SOURCE_WEB_DOWNLOAD,
                    peat_module="SEL3620",
                    description="X.509 certificate exported from the web interface",
                    extra={"page": href},
                )
            except Exception as ex:
                self.log.warning(f"Failed to record hashes for {cert_url}: {ex}")

            decoded, raw = self.decode_ssl_certificate(response.text)
            x509_obj = self.parse_decoded_ssl_certificate(decoded, raw)

            # If filename was extracted from response, use that as the key
            # to the dict.
            dict_key = href
            if file_path:
                dict_key = file_path.name
                dev.related.files.add(dict_key)

            x509_obj.annotate(dev)
            x509_cert_export[dict_key] = x509_obj.dict()

        dev.extra["x509_certificates"] = x509_cert_export
        return {"x509_certificates": x509_cert_export}

    # -------------------- End of gateway web pages --------------------


def querystr() -> str:
    return f"asfdasfowefsj={utils.utc_now()}"  # NOTE: this was previously datetime.utcnow()


def login_with_web_credentials(
    dev: DeviceData,
    login: Callable[[str, str], bool],
    web_options: Mapping,
    device_name: str = "web",
) -> bool:
    """
    Log in to the web interface of a device, with the credentials from the
    ``web`` device options.

    If credentials were verified for the device before (``verified_web_user``
    and ``verified_web_pass`` in ``dev._cache``), only those are tried.
    Otherwise, each user is tried with each password, in order: the ``user``
    option (or the ``users`` list if it's not set) with the ``pass`` option
    (or the ``passwords`` list). The first combination that works is cached
    and the user is added to ``dev.related.user``.

    This is used by :class:`~peat.modules.sel.sel_3620.SEL3620`.
    :class:`~peat.modules.sel.sel_rtac.SELRTAC` has the same loop and can use it too.

    .. warning::
       Each combination is a login attempt on the device, which may count
       towards a lockout of the account. Set the ``user`` and ``pass``
       options to make a single attempt.

    Args:
        dev: The device
        login: Function that logs in with a user and password, and returns
            if it succeeded, e.g. :meth:`SELHTTP.login_3620`
        web_options: The ``web`` device options, i.e. ``dev.options["web"]``.
            This is passed by the caller, since the device options depend on
            the module that reads them.
        device_name: Name of the kind of device, for log messages

    Returns:
        If the login succeeded
    """
    if dev._cache.get("verified_web_user") and dev._cache.get("verified_web_pass"):
        return login(dev._cache["verified_web_user"], dev._cache["verified_web_pass"])

    users = [web_options["user"]] if web_options.get("user") else web_options.get("users", [])
    passwords = (
        [web_options["pass"]] if web_options.get("pass") else web_options.get("passwords", [])
    )

    if not users or not passwords:
        log.warning(
            f"No web users or passwords configured for {device_name} login to {dev.get_id()}"
        )
        return False

    for username in users:
        log.debug(f"Attempting {device_name} login to {dev.get_id()} with user '{username}'")

        for password in passwords:
            if login(username, password):
                dev._cache["verified_web_user"] = username
                dev._cache["verified_web_pass"] = password
                dev.related.user.add(username)
                return True

    return False


__all__ = ["SELHTTP", "login_with_web_credentials"]
