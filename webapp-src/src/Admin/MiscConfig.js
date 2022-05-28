import React, { Component } from 'react';
import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';
import apiManager from '../lib/APIManager';

// To who may read this code, sorry!
// Maybe one day I'll refactor it to move modals outside of it
class MiscConfig extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      loggedIn: props.loggedIn,
      miscConfig: props.miscConfig,
      confirmTitle: "",
      confirmMessage: "",
      smtpName: false,
      smtp: {
        host: "",
        port: 25,
        "use-tls": false,
        "check-certificate": false,
        "user-lang-property": "lang",
        user: "",
        password: "",
        from: "",
        "content-type": "text/plain; charset=utf-8"
      },
      mailOnConnexion: {
        enabled: true,
        host: "",
        port: 25,
        "use-tls": false,
        "check-certificate": false,
        "user-lang-property": "lang",
        user: "",
        password: "",
        from: "",
        "content-type": "text/plain; charset=utf-8",
        templatesDisabled: false,
        templates: {},
        templatesUpdatePasswordDisabled: false,
        templatesUpdatePassword: {},
        templatesRegisterSchemeDisabled: false,
        templatesRegisterScheme: {}
      },
      errorList: {},
      currentLang: i18next.language,
      newLang: "",
      geolocation: {
        enabled: false,
        url: "",
        "output-properties": "city, country_name"
      },
      errorGeolocationList: {},
      importElement: false
    };
    
    this.addSmtp = this.addSmtp.bind(this);
    this.closeSmtpModal = this.closeSmtpModal.bind(this);
    this.changeSmtpValue = this.changeSmtpValue.bind(this);
    this.toggleSmtpValue = this.toggleSmtpValue.bind(this);
    this.addLang = this.addLang.bind(this);
    this.getImportFile = this.getImportFile.bind(this);
    this.exportSmtpRecord = this.exportSmtpRecord.bind(this);
    this.importSmtpRecord = this.importSmtpRecord.bind(this);
    this.exportMailRecord = this.exportMailRecord.bind(this);
    this.importMailRecord = this.importMailRecord.bind(this);
    this.exportGeolocRecord = this.exportGeolocRecord.bind(this);
    this.importGeolocRecord = this.importGeolocRecord.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      loggedIn: nextProps.loggedIn,
      miscConfig: nextProps.miscConfig
    });
  }
  
  addSmtp() {
    this.setState({
      smtpName: false,
      smtp: {
        host: "",
        port: 25,
        "use-tls": false,
        "check-certificate": false,
        "user-lang-property": "lang",
        user: "",
        password: "",
        from: "",
        "content-type": "text/plain; charset=utf-8"
      }
    }, () => {
      $("#smtpModal").modal({keyboard: false, show: true});
    });
  }
  
  closeSmtpModal(e, result) {
    if (result) {
      let promise, successI18n, errorI18n;
      if (this.state.smtpName) {
        promise = apiManager.glewlwydRequest("/misc/" + this.state.smtpName, "PUT", {type: "smtp", value: this.state.smtp});
        successI18n = "admin.success-api-set-misc-smtp";
        errorI18n = "admin.error-api-set-misc-smtp";
      } else {
        promise = apiManager.glewlwydRequest("/misc/smtp-"+Math.random().toString(36).substring(2, 15), "PUT", {type: "smtp", value: this.state.smtp})
        successI18n = "admin.success-api-add-misc-smtp";
        errorI18n = "admin.error-api-add-misc-smtp";
      }
      promise
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t(successI18n)});
        messageDispatcher.sendMessage('App', {type: "miscConfig"});
      })
      .fail((err) => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t(errorI18n)});
      });
    }
    $("#smtpModal").modal("hide");
  }
  
  changeSmtpValue(e, param, isNumber = false) {
    var smtp = this.state.smtp;
    if (isNumber) {
      smtp[param] = parseInt(e.target.value);
    } else {
      smtp[param] = e.target.value;
    }
    this.setState({smtp: smtp});
  }
  
  toggleSmtpValue(param) {
    var smtp = this.state.smtp;
    smtp[param] = !smtp[param];
    this.setState({smtp: smtp});
  }
  
  editSmtp(e, index) {
    this.setState({smtpName: this.state.miscConfig[index].name, smtp: this.state.miscConfig[index].value||{}}, () => {
      $("#smtpModal").modal({keyboard: false, show: true});
    });
  }
  
  deleteSmtp(e, index) {
    this.setState({smtpName: this.state.miscConfig[index].name, confirmTitle: i18next.t("admin.confirm-remove-misc-smtp-title"), confirmMessage: i18next.t("admin.confirm-remove-misc-smtp-message")}, () => {
      $("#confirmMiscModal").modal({keyboard: false, show: true});
    });
  }
  
  confirmDeleteSmtp(e, result) {
    if (result) {
      apiManager.glewlwydRequest("/misc/" + this.state.smtpName, "DELETE")
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-delete-misc-smtp")});
        messageDispatcher.sendMessage('App', {type: "miscConfig"});
      })
      .fail((err) => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-delete-misc-smtp")});
      });
    }
    $("#confirmMiscModal").modal("hide");
  }
  
  switchMailConnexion() {
    let miscConfig = this.state.miscConfig, mailOnConnexion, found = false;
    miscConfig.forEach((config) => {
      if (config.type === "mail-on-connexion") {
        found = true;
        config.value.enabled = !config.value.enabled;
        mailOnConnexion = config.value;
        apiManager.glewlwydRequest("/misc/cur-mail-on-connexion", "PUT", {type: "mail-on-connexion", value: config.value})
        .then(() => {
          messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-mail-on-connexion")});
          messageDispatcher.sendMessage('App', {type: "miscConfig"});
        })
        .fail((err) => {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-mail-on-connexion")});
        });
      }
    });
    if (!found) {
      mailOnConnexion = {
        enabled: true,
        host: "",
        port: 25,
        "use-tls": false,
        "check-certificate": false,
        "user-lang-property": "lang",
        user: "",
        password: "",
        from: "",
        "content-type": "text/plain; charset=utf-8",
        templatesDisabled: false,
        templates: {},
        templatesUpdatePasswordDisabled: false,
        templatesUpdatePassword: {},
        templatesRegisterSchemeDisabled: false,
        templatesRegisterScheme: {}
      };
      mailOnConnexion.templates[i18next.language] = {subject: "", "body-pattern": "", defaultLang: true}
      mailOnConnexion.templatesUpdatePassword[i18next.language] = {subject: "", "body-pattern": "", defaultLang: true}
      mailOnConnexion.templatesRegisterScheme[i18next.language] = {subject: "", "body-pattern": "", defaultLang: true}
    }
    this.setState({mailOnConnexion: mailOnConnexion}, () => {
      if (!found) {
        $("#mailOnConnexionModal").modal({keyboard: false, show: true});
      }
    });
  }
  
  changeMailConnexionValue(e, param, isNumber = false) {
    var mailOnConnexion = this.state.mailOnConnexion;
    if (isNumber) {
      mailOnConnexion[param] = parseInt(e.target.value);
    } else {
      mailOnConnexion[param] = e.target.value;
    }
    this.setState({mailOnConnexion: mailOnConnexion});
  }
  
  editMailConnexion() {
    let mailOnConnexion, found = false;
    this.state.miscConfig.forEach((config) => {
      if (config.type === "mail-on-connexion") {
        found = true;
        mailOnConnexion = config.value;
      }
    });
    if (found) {
      this.setState({mailOnConnexion: mailOnConnexion}, () => {
        $("#mailOnConnexionModal").modal({keyboard: false, show: true});
      });
    }
  }
  
  toggleMailConnexionValue(param) {
    var mailOnConnexion = this.state.mailOnConnexion;
    mailOnConnexion[param] = !mailOnConnexion[param];
    Object.keys(mailOnConnexion.templates).forEach(objKey => {
      mailOnConnexion.templates[objKey].defaultLang = (objKey === this.state.currentLang);
    });
    if (mailOnConnexion.templatesUpdatePassword) {
      console.log("grut 0");
      if (mailOnConnexion.templatesUpdatePassword[this.state.currentLang] === undefined) {
        console.log("grut 1");
        mailOnConnexion.templatesUpdatePassword[this.state.currentLang] = {
          subject: "",
          "body-pattern": "",
          defaultLang: true
        }
      }
      Object.keys(mailOnConnexion.templatesUpdatePassword).forEach(objKey => {
        console.log("grut 2");
        mailOnConnexion.templatesUpdatePassword[objKey].defaultLang = (objKey === this.state.currentLang);
      });
    } else {
      mailOnConnexion.templatesUpdatePassword = {};
      mailOnConnexion.templatesUpdatePassword[this.state.currentLang] = {
        subject: "",
        "body-pattern": "",
        defaultLang: true
      }
    }
    if (mailOnConnexion.templatesRegisterScheme) {
      if (mailOnConnexion.templatesRegisterScheme[this.state.currentLang] === undefined) {
        mailOnConnexion.templatesRegisterScheme[this.state.currentLang] = {
          subject: "",
          "body-pattern": "",
          defaultLang: true
        }
      }
      Object.keys(mailOnConnexion.templatesRegisterScheme).forEach(objKey => {
        mailOnConnexion.templatesRegisterScheme[objKey].defaultLang = (objKey === this.state.currentLang);
      });
    } else {
      mailOnConnexion.templatesRegisterScheme = {};
      mailOnConnexion.templatesRegisterScheme[this.state.currentLang] = {
        subject: "",
        "body-pattern": "",
        defaultLang: true
      }
    }
    console.log(mailOnConnexion);
    this.setState({mailOnConnexion: mailOnConnexion});
  }
  
  toggleLangDefault() {
    var mailOnConnexion = this.state.mailOnConnexion;
    Object.keys(mailOnConnexion.templates).forEach(objKey => {
      mailOnConnexion.templates[objKey].defaultLang = (objKey === this.state.currentLang);
    });
    Object.keys(mailOnConnexion.templatesUpdatePassword).forEach(objKey => {
      mailOnConnexion.templatesUpdatePassword[objKey].defaultLang = (objKey === this.state.currentLang);
    });
    Object.keys(mailOnConnexion.templatesRegisterScheme).forEach(objKey => {
      mailOnConnexion.templatesRegisterScheme[objKey].defaultLang = (objKey === this.state.currentLang);
    });
    this.setState({mailOnConnexion: mailOnConnexion});
  }
  
  selectSmtpConfig(e) {
    let config = this.state.miscConfig[parseInt(e.target.value)], mailOnConnexion = this.state.mailOnConnexion;
    if (config) {
      mailOnConnexion.host = config.value.host;
      mailOnConnexion.port = config.value.port;
      mailOnConnexion["use-tls"] = config.value["use-tls"];
      mailOnConnexion["check-certificate"] = config.value["check-certificate"];
      mailOnConnexion["user-lang-property"] = config.value["user-lang-property"];
      mailOnConnexion.user = config.value.user;
      mailOnConnexion.password = config.value.password;
      mailOnConnexion.from = config.value.from;
      mailOnConnexion["content-type"] = config.value["content-type"];
      this.setState({mailOnConnexion: mailOnConnexion, currentLang: i18next.language});
    }
  }
  
  changeNewLang(e) {
    this.setState({newLang: e.target.value});
  }
  
  addLang() {
    var mailOnConnexion = this.state.mailOnConnexion;
    var found = false;
    Object.keys(mailOnConnexion.templates).forEach(lang => {
      if (lang === this.state.newLang) {
        found = true;
      }
    });
    if (!found && this.state.newLang) {
      mailOnConnexion.templates[this.state.newLang] = {subject: "", "body-pattern": "", defaultLang: false};
      mailOnConnexion.templatesUpdatePassword[this.state.newLang] = {subject: "", "body-pattern": "", defaultLang: false};
      mailOnConnexion.templatesRegisterScheme[this.state.newLang] = {subject: "", "body-pattern": "", defaultLang: false};
      this.setState({mailOnConnexion: mailOnConnexion, newLang: "", currentLang: this.state.newLang});
    }
  }
  
  removeLang(lang) {
    var mailOnConnexion = this.state.mailOnConnexion;
    var currentLang = false;
    delete(mailOnConnexion.templates[lang]);
    delete(mailOnConnexion.templatesUpdatePassword[lang]);
    delete(mailOnConnexion.templatesRegisterScheme[lang]);
    if (lang == this.state.currentLang) {
      Object.keys(mailOnConnexion.templates).forEach(lang => {
        if (!currentLang) {
          currentLang = lang;
        }
      });
      this.setState({mailOnConnexion: mailOnConnexion, currentLang: currentLang});
    } else {
      this.setState({mailOnConnexion: mailOnConnexion});
    }
  }
  
  changeLang(e, lang) {
    this.setState({currentLang: lang});
  }
  
  changeTemplate(e, param) {
    var mailOnConnexion = this.state.mailOnConnexion;
    if (mailOnConnexion.templates === undefined) {
      mailOnConnexion.templates = {};
    }
    if (mailOnConnexion.templates[this.state.currentLang] === undefined) {
      mailOnConnexion.templates[this.state.currentLang] = {};
    }
    mailOnConnexion.templates[this.state.currentLang][param] = e.target.value;
    this.setState({mailOnConnexion: mailOnConnexion});
  }
  
  changeTemplateUpdatePassword(e, param) {
    var mailOnConnexion = this.state.mailOnConnexion;
    if (mailOnConnexion.templatesUpdatePassword === undefined) {
      mailOnConnexion.templatesUpdatePassword = {};
    }
    if (mailOnConnexion.templatesUpdatePassword[this.state.currentLang] === undefined) {
      mailOnConnexion.templatesUpdatePassword[this.state.currentLang] = {};
    }
    mailOnConnexion.templatesUpdatePassword[this.state.currentLang][param] = e.target.value;
    this.setState({mailOnConnexion: mailOnConnexion});
  }
  
  changeTemplateRegisterScheme(e, param) {
    var mailOnConnexion = this.state.mailOnConnexion;
    if (mailOnConnexion.templatesRegisterScheme === undefined) {
      mailOnConnexion.templatesRegisterScheme = {};
    }
    if (mailOnConnexion.templatesRegisterScheme[this.state.currentLang] === undefined) {
      mailOnConnexion.templatesRegisterScheme[this.state.currentLang] = {};
    }
    mailOnConnexion.templatesRegisterScheme[this.state.currentLang][param] = e.target.value;
    this.setState({mailOnConnexion: mailOnConnexion});
  }
  
  closeMailOnConnexionModal(e, result) {
    if (result) {
      var errorList = {}, hasError = false;
      if (!this.state.mailOnConnexion["host"]) {
        hasError = true;
        errorList["host"] = i18next.t("admin.mod-email-host-error")
      }
      if (!this.state.mailOnConnexion["from"]) {
        hasError = true;
        errorList["from"] = i18next.t("admin.mod-email-from-error")
      }
      if (!this.state.mailOnConnexion["content-type"]) {
        hasError = true;
        errorList["content-type"] = i18next.t("admin.mod-email-content-type-error")
      }
      if (!this.state.mailOnConnexion["user-lang-property"]) {
        hasError = true;
        errorList["user-lang-property"] = i18next.t("admin.mod-email-user-lang-property-error")
      }
      errorList["subject"] = "";
      errorList["body-pattern"] = "";
      if (!this.state.mailOnConnexion.templatesDisabled) {
        Object.keys(this.state.mailOnConnexion.templates).forEach(lang => {
          if (!this.state.mailOnConnexion.templates[lang]["subject"]) {
            hasError = true;
            errorList["subject"] = i18next.t("admin.mod-email-subject-error", {lang: lang})
          }
        });
      }
      if (!this.state.mailOnConnexion.templatesUpdatePasswordDisabled && this.state.mailOnConnexion.templatesUpdatePassword) {
        Object.keys(this.state.mailOnConnexion.templatesUpdatePassword).forEach(lang => {
          if (!this.state.mailOnConnexion.templatesUpdatePassword[lang]["subject"]) {
            hasError = true;
            errorList["subjectUpdatePassword"] = i18next.t("admin.mod-email-subject-error", {lang: lang})
          }
        });
      }
      if (!this.state.mailOnConnexion.templatesRegisterSchemeDisabled && this.state.mailOnConnexion.templatesRegisterScheme) {
        Object.keys(this.state.mailOnConnexion.templatesRegisterScheme).forEach(lang => {
          if (!this.state.mailOnConnexion.templatesRegisterScheme[lang]["subject"]) {
            hasError = true;
            errorList["subjectRegisterSchemeDisabled"] = i18next.t("admin.mod-email-subject-error", {lang: lang})
          }
        });
      }
      if (!hasError) {
        this.setState({errorList: {}}, () => {
          apiManager.glewlwydRequest("/misc/cur-mail-on-connexion", "PUT", {type: "mail-on-connexion", value: this.state.mailOnConnexion})
          .then(() => {
            messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-mail-on-connexion")});
            messageDispatcher.sendMessage('App', {type: "miscConfig"});
          })
          .fail((err) => {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-mail-on-connexion")});
          })
          .always(() => {
            $("#mailOnConnexionModal").modal("hide");
          });
        });
      } else {
        this.setState({errorList: errorList});
      }
    } else {
      $("#mailOnConnexionModal").modal("hide");
    }
  }

  switchGeolocation() {
    let miscConfig = this.state.miscConfig, geolocation, found = false;
    miscConfig.forEach((config) => {
      if (config.type === "ip-geolocation-api") {
        found = true;
        config.value.enabled = !config.value.enabled;
        geolocation = config.value;
        apiManager.glewlwydRequest("/misc/cur-ip-geolocation-api", "PUT", {type: "ip-geolocation-api", value: config.value})
        .then(() => {
          messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-ip-geolocation-api")});
          messageDispatcher.sendMessage('App', {type: "miscConfig"});
        })
        .fail((err) => {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-ip-geolocation-api")});
        });
      }
    });
    if (!found) {
      geolocation = {
        enabled: true,
        url: "",
        "output-properties": "city, country_name"
      };
    }
    this.setState({geolocation: geolocation}, () => {
      if (!found) {
        $("#geolocationModal").modal({keyboard: false, show: true});
      }
    });
  }
  
  closeGeolocationModal(e, result) {
    if (result) {
      var errorList = {}, hasError = false;
      if (!this.state.geolocation["url"]) {
        hasError = true;
        errorList["url"] = i18next.t("admin.misc-geolocation-url-error")
      }
      if (!this.state.geolocation["output-properties"]) {
        hasError = true;
        errorList["output-properties"] = i18next.t("admin.misc-geolocation-output-properties-error")
      }
      if (!hasError) {
        this.setState({errorGeolocationList: {}}, () => {
          apiManager.glewlwydRequest("/misc/cur-ip-geolocation-api", "PUT", {type: "ip-geolocation-api", value: this.state.geolocation})
          .then(() => {
            messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-ip-geolocation-api")});
            messageDispatcher.sendMessage('App', {type: "miscConfig"});
          })
          .fail((err) => {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-ip-geolocation-api")});
          })
          .always(() => {
            $("#geolocationModal").modal("hide");
          });
        });
      } else {
        this.setState({errorGeolocationList: errorList});
      }
    } else {
      $("#geolocationModal").modal("hide");
    }
  }

  changeGeolocationValue(e, param) {
    var geolocation = this.state.geolocation;
    geolocation[param] = e.target.value;
    this.setState({geolocation: geolocation});
  }
  
  editGeolocation() {
    let geolocation, found = false;
    this.state.miscConfig.forEach((config) => {
      if (config.type === "ip-geolocation-api") {
        found = true;
        geolocation = config.value;
      }
    });
    if (found) {
      this.setState({geolocation: geolocation}, () => {
        $("#geolocationModal").modal({keyboard: false, show: true});
      });
    }
  }
  
  exportSmtpRecord() {
    var exported = Object.assign({}, this.state.smtp);
    var $anchor = $("#record-download");
    $anchor.attr("href", "data:application/octet-stream;base64,"+btoa(JSON.stringify(exported)));
    $anchor.attr("download", (this.state.smtp.host)+".json");
    $anchor[0].click();
  }
  
  importSmtpRecord() {
    this.setState({importElement: "smtp"}, () => {
      $("#record-upload").click();
    });
  }
  
  exportMailRecord() {
    var exported = Object.assign({}, this.state.mailOnConnexion);
    var $anchor = $("#record-download");
    $anchor.attr("href", "data:application/octet-stream;base64,"+btoa(JSON.stringify(exported)));
    $anchor.attr("download", "mailOnConnexion.json");
    $anchor[0].click();
  }
  
  importMailRecord() {
    this.setState({importElement: "mail"}, () => {
      $("#record-upload").click();
    });
  }
  
  exportGeolocRecord() {
    var exported = Object.assign({}, this.state.geolocation);
    var $anchor = $("#record-download");
    $anchor.attr("href", "data:application/octet-stream;base64,"+btoa(JSON.stringify(exported)));
    $anchor.attr("download", "geolocation.json");
    $anchor[0].click();
  }
  
  importGeolocRecord() {
    this.setState({importElement: "geolocation"}, () => {
      $("#record-upload").click();
    });
  }
  
  getImportFile(e) {
    var file = e.target.files[0];
    var fr = new FileReader();
    fr.onload = (ev2) => {
      try {
        let imported = JSON.parse(ev2.target.result);
        if (this.state.importElement === "smtp") {
          this.setState({smtp: imported});
        } else if (this.state.importElement === "mail") {
          this.setState({mailOnConnexion: imported});
        } else if (this.state.importElement === "geolocation") {
          this.setState({geolocation: imported});
        }
      } catch (err) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.import-error")});
      }
    };
    fr.readAsText(file);
  }
  
  render() {
    let smtpList = [], switchMailConnexionButton, mailConnexionEditDisabled = true, smtpConfigList = [], switchGeolocationButton, geolocationDisabled = true;
    switchMailConnexionButton =
      <button type="button" className="btn btn-secondary" onClick={(e) => this.switchMailConnexion()} title={i18next.t("admin.switch-on")}>
        <i className="fas fa-toggle-off"></i>
      </button>
    switchGeolocationButton =
      <button type="button" className="btn btn-secondary" onClick={(e) => this.switchGeolocation()} title={i18next.t("admin.switch-on")}>
        <i className="fas fa-toggle-off"></i>
      </button>
    this.state.miscConfig.forEach((config, index) => {
      if (config.type === "smtp") {
        let summary;
        if (config.value) {
          summary = "Host: "+config.value.host;
          smtpConfigList.push(
            <option key={index} value={index}>{index + " - " + summary}</option>
          );
        }
        smtpList.push(
          <tr key={index}>
            <td>{summary}</td>
            <td className="text-right">
              <div className="btn-group" role="group">
                <button type="button" className="btn btn-secondary" onClick={(e) => this.editSmtp(e, index)} title={i18next.t("admin.edit")}>
                  <i className="fas fa-edit"></i>
                </button>
                <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteSmtp(e, index)} title={i18next.t("admin.delete")}>
                  <i className="fas fa-trash"></i>
                </button>
              </div>
            </td>
          </tr>
        );
      } else if (config.type === "mail-on-connexion") {
        if (config.value.enabled) {
          switchMailConnexionButton =
            <button type="button" className="btn btn-secondary" onClick={(e) => this.switchMailConnexion()} title={i18next.t("admin.switch-off")}>
              <i className="fas fa-toggle-on"></i>
            </button>
          mailConnexionEditDisabled = false;
        }
      } else if (config.type === "ip-geolocation-api") {
        if (config.value.enabled) {
          switchGeolocationButton =
            <button type="button" className="btn btn-secondary" onClick={(e) => this.switchGeolocation()} title={i18next.t("admin.switch-off")}>
              <i className="fas fa-toggle-on"></i>
            </button>
          geolocationDisabled = false;
        }
      }
    });
    let langList = [];
    langList.push(
    <div key={-2} className="form-group">
      <div className="input-group mb-3">
        <input type="text" className="form-control" id="mod-email-new-lang" placeholder={i18next.t("admin.mod-email-new-lang-ph")} value={this.state.newLang} onChange={(e) => this.changeNewLang(e)} />
        <div className="input-group-append">
          <button type="button" onClick={this.addLang} className="btn btn-outline-primary">{i18next.t("admin.mod-email-new-lang-add")}</button>
        </div>
      </div>
    </div>
    );
    langList.push(<div key={-1} className="dropdown-divider"></div>);
    Object.keys(this.state.mailOnConnexion.templates).forEach((lang, index) => {
      langList.push(
      <div key={index*2} className="btn-group btn-group-justified">
        <button type="button" className="btn btn-primary" disabled={true}>{lang}</button>
        <button type="button" onClick={(e) => this.removeLang(lang)} className="btn btn-primary" disabled={this.state.mailOnConnexion.templates[lang].defaultLang}>{i18next.t("admin.mod-email-new-lang-remove")}</button>
        <button type="button" onClick={(e) => this.changeLang(e, lang)} className="btn btn-primary">{i18next.t("admin.mod-email-new-lang-select")}</button>
      </div>
      );
      langList.push(<div key={(index*2)+1} className="dropdown-divider"></div>);
    });
    let templateMailOnConnexion = {};
    let templateMailOnUpdatePassword = {};
    let templateMailOnRegisterScheme = {};
    if (this.state.mailOnConnexion.templates) {
      templateMailOnConnexion = this.state.mailOnConnexion.templates[this.state.currentLang]||{};
    }
    let defaultLang = false;
    if (this.state.mailOnConnexion.templates[this.state.currentLang]) {
      defaultLang = this.state.mailOnConnexion.templates[this.state.currentLang].defaultLang;
    }
    if (this.state.mailOnConnexion.templatesUpdatePassword) {
      templateMailOnUpdatePassword = this.state.mailOnConnexion.templatesUpdatePassword[this.state.currentLang]||{defaultLang: defaultLang};
    } else {
      templateMailOnUpdatePassword = {
        subject: "",
        "body-pattern": "",
        defaultLang: defaultLang
      }
    }
    if (this.state.mailOnConnexion.templatesRegisterScheme) {
      templateMailOnRegisterScheme = this.state.mailOnConnexion.templatesRegisterScheme[this.state.currentLang]||{defaultLang: defaultLang};
    } else {
      templateMailOnRegisterScheme = {
        subject: "",
        "body-pattern": "",
        defaultLang: defaultLang
      }
    }
		return (
      <div>
        <div className="table-responsive">
        <h4>
          {i18next.t("admin.misc-smtp-list-title")}
          <button type="button" className="btn btn-secondary btn-icon-right" onClick={this.addSmtp} title={i18next.t("admin.add")}>
            <i className="fas fa-plus"></i>
          </button>
        </h4>
          <table className="table table-striped">
            <thead>
              <tr>
                <th>
                  {i18next.t("admin.misc-smtp-summary")}
                </th>
                <th>
                </th>
              </tr>
            </thead>
            <tbody>
              {smtpList}
            </tbody>
          </table>
        </div>
        <hr/>
        <h4>
          {i18next.t("admin.misc-send-mail-on-new-connexion")}
        </h4>
        <div className="text-right">
          <div className="btn-group" role="group">
            {switchMailConnexionButton}
            <button type="button" className="btn btn-secondary" onClick={(e) => this.editMailConnexion()} title={i18next.t("admin.edit")} disabled={mailConnexionEditDisabled}>
              <i className="fas fa-edit"></i>
            </button>
          </div>
        </div>
        <hr/>
        <h4>
          {i18next.t("admin.misc-ip-geolocation-api")}
        </h4>
        <div className="text-right">
          <div className="btn-group" role="group">
            {switchGeolocationButton}
            <button type="button" className="btn btn-secondary" onClick={(e) => this.editGeolocation()} title={i18next.t("admin.edit")} disabled={geolocationDisabled}>
              <i className="fas fa-edit"></i>
            </button>
          </div>
        </div>
        <div className="modal fade on-top" id="smtpModal" tabIndex="-1" role="dialog" aria-labelledby="smtpModalLabel" aria-hidden="true">
          <div className="modal-dialog modal-lg" role="document">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title" id="smtpModalLabel">{i18next.t("admin.modal-misc-smtp-title")}</h5>
                <div className="btn-group btn-icon-right" role="group">
                  <button disabled={!this.state.smtpName} type="button" className="btn btn-secondary" onClick={this.exportSmtpRecord} title={i18next.t("admin.export")}>
                    <i className="fas fa-download"></i>
                  </button>
                  <button type="button" className="btn btn-secondary" onClick={this.importSmtpRecord} title={i18next.t("admin.import")}>
                    <i className="fas fa-upload"></i>
                  </button>
                </div>
                <button type="button" className="close" aria-label={i18next.t("modal.close")} onClick={(e) => this.closeSmtpModal(e, false)}>
                  <span aria-hidden="true">&times;</span>
                </button>
              </div>
              <div className="modal-body">
                <form className="needs-validation" noValidate>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-host">{i18next.t("admin.mod-email-host")}</label>
                      </div>
                      <input type="text" className="form-control" id="smtpHost" placeholder={i18next.t("admin.mod-email-host-ph")} value={this.state.smtp.host} onChange={(e) => this.changeSmtpValue(e, "host")} />
                    </div>
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-port">{i18next.t("admin.mod-email-port")}</label>
                      </div>
                      <input type="number" min="0" max="65536" step="1" className="form-control" id="mod-email-port" onChange={(e) => this.changeSmtpValue(e, "port", true)} value={this.state.smtp.port} placeholder={i18next.t("admin.mod-email-port-ph")} />
                    </div>
                  </div>
                  <div className="form-group form-check">
                    <input type="checkbox" className="form-check-input" id="mod-email-use-tls" onChange={(e) => this.toggleSmtpValue("use-tls")} checked={this.state.smtp["use-tls"]} />
                    <label className="form-check-label" htmlFor="mod-email-use-tls">{i18next.t("admin.mod-email-use-tls")}</label>
                  </div>
                  <div className="form-group form-check">
                    <input type="checkbox" className="form-check-input" disabled={!this.state.smtp["use-tls"]} id="mod-email-check-certificate" onChange={(e) => this.toggleSmtpValue("check-certificate")} checked={this.state.smtp["check-certificate"]} />
                    <label className="form-check-label" htmlFor="mod-email-check-certificate">{i18next.t("admin.mod-email-check-certificate")}</label>
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-user-lang-property">{i18next.t("admin.mod-email-user-lang-property")}</label>
                      </div>
                      <input type="text" className="form-control" id="mod-email-user-lang-property" onChange={(e) => this.changeSmtpValue(e, "user-lang-property")} value={this.state.smtp["user-lang-property"]} placeholder={i18next.t("admin.mod-email-user-lang-property-ph")} />
                    </div>
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-user">{i18next.t("admin.mod-email-user")}</label>
                      </div>
                      <input type="text" className="form-control" id="mod-email-user" onChange={(e) => this.changeSmtpValue(e, "user")} value={this.state.smtp.user} placeholder={i18next.t("admin.mod-email-user-ph")} />
                    </div>
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-password">{i18next.t("admin.mod-email-password")}</label>
                      </div>
                      <input type="password" className="form-control" id="mod-email-password" onChange={(e) => this.changeSmtpValue(e, "password")} value={this.state.smtp["password"]} placeholder={i18next.t("admin.mod-email-password-ph")} />
                    </div>
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-from">{i18next.t("admin.mod-email-from")}</label>
                      </div>
                      <input type="text" className="form-control" id="mod-email-from" onChange={(e) => this.changeSmtpValue(e, "from")} value={this.state.smtp.from} placeholder={i18next.t("admin.mod-email-from-ph")} />
                    </div>
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-content-type">{i18next.t("admin.mod-email-content-type")}</label>
                      </div>
                      <input type="text" className="form-control" id="mod-content-type-from" onChange={(e) => this.changeSmtpValue(e, "content-type")} value={this.state.smtp["content-type"]} placeholder={i18next.t("admin.mod-email-content-type-ph")} />
                    </div>
                  </div>
                </form>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={(e) => this.closeSmtpModal(e, false)}>{i18next.t("modal.close")}</button>
                <button type="button" className="btn btn-primary" onClick={(e) => this.closeSmtpModal(e, true)}>{i18next.t("modal.ok")}</button>
              </div>
            </div>
          </div>
        </div>
        <div className="modal fade on-top" id="mailOnConnexionModal" tabIndex="-1" role="dialog" aria-labelledby="mailOnConnexionModalLabel" aria-hidden="true">
          <div className="modal-dialog modal-lg" role="document">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title" id="mailOnConnexionModalLabel">{i18next.t("admin.modal-misc-mail-on-connexion-title")}</h5>
                <div className="btn-group btn-icon-right" role="group">
                  <button type="button" className="btn btn-secondary" onClick={this.exportMailRecord} title={i18next.t("admin.export")}>
                    <i className="fas fa-download"></i>
                  </button>
                  <button type="button" className="btn btn-secondary" onClick={this.importMailRecord} title={i18next.t("admin.import")}>
                    <i className="fas fa-upload"></i>
                  </button>
                </div>
                <button type="button" className="close" aria-label={i18next.t("modal.close")} onClick={(e) => this.closeMailOnConnexionModal(e, false)}>
                  <span aria-hidden="true">&times;</span>
                </button>
              </div>
              <div className="modal-body">
                <form className="needs-validation" noValidate>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="smtp-template">{i18next.t("admin.smtp-config")}</label>
                      </div>
                      <select className="form-control" onChange={(e) => {this.selectSmtpConfig(e)}}>
                        <option value={-1}>{i18next.t("admin.smtp-config-none")}</option>
                        {smtpConfigList}
                      </select>
                    </div>
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-host">{i18next.t("admin.mod-email-host")}</label>
                      </div>
                      <input type="text" className={this.state.errorList["host"]?"form-control is-invalid":"form-control"} id="mod-email-host" onChange={(e) => this.changeMailConnexionValue(e, "host")} value={this.state.mailOnConnexion["host"]} placeholder={i18next.t("admin.mod-email-host-ph")} />
                    </div>
                    {this.state.errorList["host"]?<span className="error-input">{this.state.errorList["host"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-port">{i18next.t("admin.mod-email-port")}</label>
                      </div>
                      <input type="number" min="0" max="65536" step="1" className="form-control" id="mod-email-port" onChange={(e) => this.changeMailConnexionValue(e, "port", true)} value={this.state.mailOnConnexion["port"]} placeholder={i18next.t("admin.mod-email-port-ph")} />
                    </div>
                  </div>
                  <div className="form-group form-check">
                    <input type="checkbox" className="form-check-input" id="mod-email-connexion-use-tls" onChange={(e) => this.toggleMailConnexionValue("use-tls")} checked={this.state.mailOnConnexion["use-tls"]||false} />
                    <label className="form-check-label" htmlFor="mod-email-connexion-use-tls">{i18next.t("admin.mod-email-use-tls")}</label>
                  </div>
                  <div className="form-group form-check">
                    <input type="checkbox" className="form-check-input" disabled={!this.state.mailOnConnexion["use-tls"]} id="mod-email-connexion-check-certificate" onChange={(e) => this.toggleMailConnexionValue("check-certificate")} checked={this.state.mailOnConnexion["check-certificate"]||false} />
                    <label className="form-check-label" htmlFor="mod-email-connexion-check-certificate">{i18next.t("admin.mod-email-check-certificate")}</label>
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-user">{i18next.t("admin.mod-email-user")}</label>
                      </div>
                      <input type="text" className={this.state.errorList["user"]?"form-control is-invalid":"form-control"} id="mod-email-user" onChange={(e) => this.changeMailConnexionValue(e, "user")} value={this.state.mailOnConnexion["user"]} placeholder={i18next.t("admin.mod-email-user-ph")} />
                    </div>
                    {this.state.errorList["user"]?<span className="error-input">{this.state.errorList["user"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-password">{i18next.t("admin.mod-email-password")}</label>
                      </div>
                      <input type="password" className="form-control" id="mod-email-password" onChange={(e) => this.changeMailConnexionValue(e, "password")} value={this.state.mailOnConnexion["password"]} placeholder={i18next.t("admin.mod-email-password-ph")} />
                    </div>
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-from">{i18next.t("admin.mod-email-from")}</label>
                      </div>
                      <input type="text" className={this.state.errorList["from"]?"form-control is-invalid":"form-control"} id="mod-email-from" onChange={(e) => this.changeMailConnexionValue(e, "from")} value={this.state.mailOnConnexion["from"]} placeholder={i18next.t("admin.mod-email-from-ph")} />
                    </div>
                    {this.state.errorList["from"]?<span className="error-input">{this.state.errorList["from"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-content-type">{i18next.t("admin.mod-email-content-type")}</label>
                      </div>
                      <input type="text" className={this.state.errorList["content-type"]?"form-control is-invalid":"form-control"} id="mod-content-type-from" onChange={(e) => this.changeMailConnexionValue(e, "content-type")} value={this.state.mailOnConnexion["content-type"]} placeholder={i18next.t("admin.mod-email-content-type-ph")} />
                    </div>
                    {this.state.errorList["content-type"]?<span className="error-input">{this.state.errorList["content-type"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-user-lang-property">{i18next.t("admin.mod-email-user-lang-property")}</label>
                      </div>
                      <input type="text" className={this.state.errorList["user-lang-property"]?"form-control is-invalid":"form-control"} id="mod-email-user-lang-property" onChange={(e) => this.changeMailConnexionValue(e, "user-lang-property")} value={this.state.mailOnConnexion["user-lang-property"]} placeholder={i18next.t("admin.mod-email-user-lang-property-ph")} />
                    </div>
                    {this.state.errorList["user-lang-property"]?<span className="error-input">{this.state.errorList["user-lang-property"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-lang">{i18next.t("admin.mod-email-lang")}</label>
                      </div>
                      <div className="dropdown">
                        <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-email-lang" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                          {this.state.currentLang}
                        </button>
                        <div className="dropdown-menu" aria-labelledby="mod-email-lang">
                          {langList}
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="form-group form-check">
                    <input type="checkbox" className="form-check-input" id="mod-email-lang-default" onChange={(e) => this.toggleLangDefault()} checked={templateMailOnConnexion.defaultLang} />
                    <label className="form-check-label" htmlFor="mod-email-lang-default">{i18next.t("admin.mod-email-lang-default")}</label>
                  </div>
                  <h3>
                    {i18next.t("admin.mail-on-connexion-title")}
                  </h3>
                  <div className="form-group form-check">
                    <input type="checkbox"
                           className="form-check-input"
                           id="mail-on-connexion-enabled"
                           onChange={(e) => this.toggleMailConnexionValue("templatesDisabled")}
                           checked={!this.state.mailOnConnexion.templatesDisabled} />
                    <label className="form-check-label" htmlFor="mail-on-connexion-enabled">{i18next.t("admin.enabled")}</label>
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-subject">{i18next.t("admin.mod-email-subject")}</label>
                      </div>
                      <input type="text"
                             className={this.state.errorList["subject"]?"form-control is-invalid":"form-control"}
                             id="mod-email-subject"
                             disabled={this.state.mailOnConnexion.templatesDisabled}
                             onChange={(e) => this.changeTemplate(e, "subject")}
                             value={templateMailOnConnexion["subject"]}
                             placeholder={i18next.t("admin.mail-on-connexion-subject-ph")} />
                    </div>
                    {this.state.errorList["subject"]?<span className="error-input">{this.state.errorList["subject"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <span className="input-group-text" >{i18next.t("admin.mail-on-connexion-body-pattern")}</span>
                      </div>
                      <textarea className="form-control"
                                id="mod-email-body-pattern"
                                disabled={this.state.mailOnConnexion.templatesDisabled}
                                onChange={(e) => this.changeTemplate(e, "body-pattern")}
                                placeholder={i18next.t("admin.mail-on-connexion-body-pattern-ph")}
                                value={templateMailOnConnexion["body-pattern"]}></textarea>
                    </div>
                  </div>
                  <hr/>
                  <h3>
                    {i18next.t("admin.mail-on-update-password-title")}
                  </h3>
                  <div className="form-group form-check">
                    <input type="checkbox"
                           className="form-check-input"
                           id="mail-update-password-enabled"
                           onChange={(e) => this.toggleMailConnexionValue("templatesUpdatePasswordDisabled")}
                           checked={!this.state.mailOnConnexion.templatesUpdatePasswordDisabled} />
                    <label className="form-check-label" htmlFor="mail-update-password-enabled">{i18next.t("admin.enabled")}</label>
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-update-password-subject">{i18next.t("admin.mod-email-subject")}</label>
                      </div>
                      <input type="text"
                             className={this.state.errorList["subjectUpdatePassword"]?"form-control is-invalid":"form-control"}
                             id="mod-email-update-password-subject"
                             disabled={this.state.mailOnConnexion.templatesUpdatePasswordDisabled}
                             onChange={(e) => this.changeTemplateUpdatePassword(e, "subject")}
                             value={templateMailOnUpdatePassword["subject"]}
                             placeholder={i18next.t("admin.mail-on-update-password-subject-ph")} />
                    </div>
                    {this.state.errorList["subjectUpdatePassword"]?<span className="error-input">{this.state.errorList["subjectUpdatePassword"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <span className="input-group-text" >{i18next.t("admin.mail-on-update-password-body-pattern")}</span>
                      </div>
                      <textarea className="form-control"
                                id="mod-email-update-password-body-pattern"
                                disabled={this.state.mailOnConnexion.templatesUpdatePasswordDisabled}
                                onChange={(e) => this.changeTemplateUpdatePassword(e, "body-pattern")}
                                placeholder={i18next.t("admin.mail-on-connexion-body-pattern-ph")}
                                value={templateMailOnUpdatePassword["body-pattern"]}></textarea>
                    </div>
                  </div>
                  <hr/>
                  <h3>
                    {i18next.t("admin.mail-on-register-scheme-title")}
                  </h3>
                  <div className="form-group form-check">
                    <input type="checkbox"
                           className="form-check-input"
                           id="mail-register-scheme-enabled"
                           onChange={(e) => this.toggleMailConnexionValue("templatesRegisterSchemeDisabled")}
                           checked={!this.state.mailOnConnexion.templatesRegisterSchemeDisabled} />
                    <label className="form-check-label" htmlFor="mail-register-scheme-enabled">{i18next.t("admin.enabled")}</label>
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-email-register-scheme-subject">{i18next.t("admin.mod-email-subject")}</label>
                      </div>
                      <input type="text"
                             className={this.state.errorList["subjectRegisterSchemeDisabled"]?"form-control is-invalid":"form-control"}
                             id="mod-email-register-scheme-subject"
                             disabled={this.state.mailOnConnexion.templatesRegisterSchemeDisabled}
                             onChange={(e) => this.changeTemplateRegisterScheme(e, "subject")}
                             value={templateMailOnRegisterScheme["subject"]}
                             placeholder={i18next.t("admin.mail-on-register-scheme-subject-ph")} />
                    </div>
                    {this.state.errorList["subjectRegisterSchemeDisabled"]?<span className="error-input">{this.state.errorList["subjectRegisterSchemeDisabled"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <span className="input-group-text" >{i18next.t("admin.mail-on-register-scheme-body-pattern")}</span>
                      </div>
                      <textarea className="form-control"
                                id="mod-email-register-scheme-body-pattern"
                                disabled={this.state.mailOnConnexion.templatesRegisterSchemeDisabled}
                                onChange={(e) => this.changeTemplateRegisterScheme(e, "body-pattern")}
                                placeholder={i18next.t("admin.mail-on-register-scheme-body-pattern-ph")}
                                value={templateMailOnRegisterScheme["body-pattern"]}></textarea>
                    </div>
                  </div>
                </form>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={(e) => this.closeMailOnConnexionModal(e, false)}>{i18next.t("modal.close")}</button>
                <button type="button" className="btn btn-primary" onClick={(e) => this.closeMailOnConnexionModal(e, true)}>{i18next.t("modal.ok")}</button>
              </div>
            </div>
          </div>
        </div>
        <div className="modal fade on-top" id="geolocationModal" tabIndex="-1" role="dialog" aria-labelledby="geolocationModalLabel" aria-hidden="true">
          <div className="modal-dialog modal-lg" role="document">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title" id="geolocationModalLabel">{i18next.t("admin.modal-misc-geolocation-title")}</h5>
                <div className="btn-group btn-icon-right" role="group">
                  <button type="button" className="btn btn-secondary" onClick={this.exportGeolocRecord} title={i18next.t("admin.export")}>
                    <i className="fas fa-download"></i>
                  </button>
                  <button type="button" className="btn btn-secondary" onClick={this.importGeolocRecord} title={i18next.t("admin.import")}>
                    <i className="fas fa-upload"></i>
                  </button>
                </div>
                <button type="button" className="close" aria-label={i18next.t("modal.close")} onClick={(e) => this.closeGeolocationModal(e, false)}>
                  <span aria-hidden="true">&times;</span>
                </button>
              </div>
              <div className="modal-body">
                <form className="needs-validation" noValidate>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="misc-geolocation-url">{i18next.t("admin.misc-geolocation-url")}</label>
                      </div>
                      <input type="text" className={this.state.errorList["url"]?"form-control is-invalid":"form-control"} id="misc-geolocation-url" onChange={(e) => this.changeGeolocationValue(e, "url")} value={this.state.geolocation["url"]} placeholder={i18next.t("admin.misc-geolocation-url-ph")} />
                    </div>
                    {this.state.errorList["url"]?<span className="error-input">{this.state.errorList["url"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="misc-geolocation-output-properties">{i18next.t("admin.misc-geolocation-output-properties")}</label>
                      </div>
                      <input type="text" className={this.state.errorList["output-properties"]?"form-control is-invalid":"form-control"} id="misc-geolocation-output-properties" onChange={(e) => this.changeGeolocationValue(e, "output-properties")} value={this.state.geolocation["output-properties"]} placeholder={i18next.t("admin.misc-geolocation-output-properties-ph")} />
                    </div>
                    {this.state.errorList["output-properties"]?<span className="error-input">{this.state.errorList["output-properties"]}</span>:""}
                  </div>
                </form>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={(e) => this.closeGeolocationModal(e, false)}>{i18next.t("modal.close")}</button>
                <button type="button" className="btn btn-primary" onClick={(e) => this.closeGeolocationModal(e, true)}>{i18next.t("modal.ok")}</button>
              </div>
            </div>
          </div>
        </div>
        <div className="modal fade on-top" id="confirmMiscModal" tabIndex="-1" role="dialog" aria-labelledby="confirmMiscModalLabel" aria-hidden="true">
          <div className="modal-dialog" role="document">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title" id="confirmMiscModalLabel">{this.state.confirmTitle}</h5>
                <button type="button" className="close" aria-label={i18next.t("modal.close")} onClick={(e) => this.confirmDeleteSmtp(e, false)}>
                  <span aria-hidden="true">&times;</span>
                </button>
              </div>
              <div className="modal-body">
                {this.state.confirmMessage}
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={(e) => this.confirmDeleteSmtp(e, false)}>{i18next.t("modal.close")}</button>
                <button type="button" className="btn btn-primary" onClick={(e) => this.confirmDeleteSmtp(e, true)}>{i18next.t("modal.ok")}</button>
              </div>
            </div>
          </div>
        </div>
        <input type="file"
               className="upload"
               id="record-upload"
               onChange={this.getImportFile} />
        <a className="upload" id="record-download" />
      </div>
		);
  }
}

export default MiscConfig;
