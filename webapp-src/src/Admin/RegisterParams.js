import React, { Component } from 'react';
import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';

class RegisterParams extends Component {
  constructor(props) {
    super(props);

    if (!props.mod) {
      props.mod = {parameters: {}};
    }
    
    if (props.mod.parameters["registration"] === undefined && !props.mod.parameters["session-key"]) {
      props.mod.parameters["registration"] = false;
    } else if (props.mod.parameters["registration"] === undefined && props.mod.parameters["session-key"]) {
      props.mod.parameters["registration"] = true;
    }

    if (!props.mod.parameters["verification-code-length"]) {
      props.mod.parameters["verification-code-length"] = 8;
    }

    if (!props.mod.parameters["verification-code-duration"]) {
      props.mod.parameters["verification-code-duration"] = 600;
    }

    if (!props.mod.parameters["host"]) {
      props.mod.parameters["host"] = "";
    }

    if (!props.mod.parameters["port"]) {
      props.mod.parameters["port"] = 0;
    }

    if (props.mod.parameters["verify-email"] === undefined) {
      props.mod.parameters["verify-email"] = false;
    }

    if (props.mod.parameters["email-is-username"] === undefined) {
      props.mod.parameters["email-is-username"] = false;
    }

    if (props.mod.parameters["scope"] === undefined) {
      props.mod.parameters["scope"] = [props.config.profile_scope];
    }

    if (!props.mod.parameters["set-password"]) {
      props.mod.parameters["set-password"] = "always";
    }

    if (props.mod.parameters["schemes"] === undefined) {
      props.mod.parameters["schemes"] = [];
    }

    if (!props.mod.parameters["session-key"]) {
      props.mod.parameters["session-key"] = "G_REGISTER_SESSION";
    }

    if (!props.mod.parameters["session-duration"]) {
      props.mod.parameters["session-duration"] = 3600;
    }

    if (!props.mod.parameters["subject"]) {
      props.mod.parameters["subject"] = "Confirm registration";
    }

    if (!props.mod.parameters["content-type"]) {
      props.mod.parameters["content-type"] = "text/plain; charset=utf-8";
    }

    if (!props.mod.parameters["from"]) {
      props.mod.parameters["from"] = "";
    }

    if (!props.mod.parameters["templates"]) {
      props.mod.parameters["templates"] = {};
    }

    if (!props.mod.parameters["templates"][i18next.language]) {
      props.mod.parameters["templates"][i18next.language] = {
        subject: props.mod.parameters.subject||"Confirm registration", 
        "body-pattern": props.mod.parameters["body-pattern"]||"The code is {CODE}\n\n"+window.location.href.split('?')[0].split('#')[0]+"/"+props.config.ProfileUrl+"?register=<your_registration_plugin_name>&token={TOKEN}", 
        defaultLang: true
      };
    }

    if (props.mod.parameters["update-email"] === undefined) {
      props.mod.parameters["update-email"] = false;
    }

    if (!props.mod.parameters["update-email-content-type"]) {
      props.mod.parameters["update-email-content-type"] = "text/plain; charset=utf-8";
    }

    if (!props.mod.parameters["templatesUpdateEmail"]) {
      props.mod.parameters["templatesUpdateEmail"] = {};
    }

    if (!props.mod.parameters["templatesUpdateEmail"][i18next.language]) {
      props.mod.parameters["templatesUpdateEmail"][i18next.language] = {
        subject: "Update e-mail address", 
        "body-pattern": "Click on the following link: "+window.location.href.split('?')[0].split('#')[0]+"/"+props.config.ProfileUrl+"?updateEmail=<your_registration_plugin_name>&token={TOKEN}", 
        defaultLang: true
      };
    }

    if (!props.mod.parameters["update-email-token-duration"]) {
      props.mod.parameters["update-email-token-duration"] = 600;
    }
    
    if (!props.mod.parameters["update-email-from"]) {
      props.mod.parameters["update-email-from"] = "";
    }

    if (props.mod.parameters["reset-credentials"] === undefined) {
      props.mod.parameters["reset-credentials"] = false;
    }

    if (!props.mod.parameters["reset-credentials-session-key"]) {
      props.mod.parameters["reset-credentials-session-key"] = "G_CREDENTIALS_SESSION";
    }

    if (!props.mod.parameters["reset-credentials-session-duration"]) {
      props.mod.parameters["reset-credentials-session-duration"] = 3600;
    }

    if (props.mod.parameters["reset-credentials-email"] === undefined) {
      props.mod.parameters["reset-credentials-email"] = false;
    }

    if (!props.mod.parameters["reset-credentials-content-type"]) {
      props.mod.parameters["reset-credentials-content-type"] = "text/plain; charset=utf-8";
    }

    if (!props.mod.parameters["templatesResetCredentials"]) {
      props.mod.parameters["templatesResetCredentials"] = {};
    }

    if (!props.mod.parameters["templatesResetCredentials"][i18next.language]) {
      props.mod.parameters["templatesResetCredentials"][i18next.language] = {
        subject: "Lost credentials", 
        "body-pattern": "Click on the following link: "+window.location.href.split('?')[0].split('#')[0]+"/"+props.config.ProfileUrl+"?resetCredentials=<your_registration_plugin_name>&token={TOKEN}", 
        defaultLang: true
      };
    }

    if (!props.mod.parameters["reset-credentials-token-duration"]) {
      props.mod.parameters["reset-credentials-token-duration"] = 600;
    }
    
    if (!props.mod.parameters["reset-credentials-from"]) {
      props.mod.parameters["reset-credentials-from"] = "";
    }

    if (props.mod.parameters["reset-credentials-code"] === undefined) {
      props.mod.parameters["reset-credentials-code"] = false;
    }
    
    if (!props.mod.parameters["reset-credentials-code-list-size"]) {
      props.mod.parameters["reset-credentials-code-list-size"] = 4;
    }

    if (!props.mod.parameters["reset-credentials-code-property"]) {
      props.mod.parameters["reset-credentials-code-property"] = "reset-credentials-code";
    }

    this.state = {
      config: props.config,
      modSchemes: props.modSchemes,
      mod: props.mod,
      role: props.role,
      check: props.check,
      hasError: false,
      errorList: {},
      currentLang: i18next.language,
      newLang: "",
      currentLangUpdateEmail: i18next.language,
      newLangUpdateEmail: "",
      currentLangResetCredentials: i18next.language,
      newLangResetCredentials: ""
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.checkParameters = this.checkParameters.bind(this);
    this.addScope = this.addScope.bind(this);
    this.deleteScope = this.deleteScope.bind(this);
    this.addScheme = this.addScheme.bind(this);
    this.changeLang = this.changeLang.bind(this);
    this.toggleLangDefault = this.toggleLangDefault.bind(this);
    this.changeNewLang = this.changeNewLang.bind(this);
    this.addLang = this.addLang.bind(this);
    this.removeLang = this.removeLang.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    if (!nextProps.mod) {
      nextProps.mod = {parameters: {}};
    }
    
    if (nextProps.mod.parameters["registration"] === undefined && !nextProps.mod.parameters["session-key"]) {
      nextProps.mod.parameters["registration"] = false;
    } else if (nextProps.mod.parameters["registration"] === undefined && nextProps.mod.parameters["session-key"]) {
      nextProps.mod.parameters["registration"] = true;
    }

    if (!nextProps.mod.parameters["verification-code-length"]) {
      nextProps.mod.parameters["verification-code-length"] = 8;
    }

    if (!nextProps.mod.parameters["verification-code-duration"]) {
      nextProps.mod.parameters["verification-code-duration"] = 600;
    }

    if (!nextProps.mod.parameters["host"]) {
      nextProps.mod.parameters["host"] = "";
    }

    if (!nextProps.mod.parameters["port"]) {
      nextProps.mod.parameters["port"] = 0;
    }

    if (nextProps.mod.parameters["verify-email"] === undefined) {
      nextProps.mod.parameters["verify-email"] = false;
    }

    if (nextProps.mod.parameters["email-is-username"] === undefined) {
      nextProps.mod.parameters["email-is-username"] = false;
    }

    if (nextProps.mod.parameters["scope"] === undefined) {
      nextProps.mod.parameters["scope"] = [nextProps.config.profile_scope];
    }

    if (!nextProps.mod.parameters["set-password"]) {
      nextProps.mod.parameters["set-password"] = "always";
    }

    if (nextProps.mod.parameters["schemes"] === undefined) {
      nextProps.mod.parameters["schemes"] = [];
    }

    if (!nextProps.mod.parameters["session-key"]) {
      nextProps.mod.parameters["session-key"] = "G_REGISTER_SESSION";
    }

    if (!nextProps.mod.parameters["session-duration"]) {
      nextProps.mod.parameters["session-duration"] = 3600;
    }

    if (!nextProps.mod.parameters["from"]) {
      nextProps.mod.parameters["from"] = "";
    }

    if (!nextProps.mod.parameters["content-type"]) {
      nextProps.mod.parameters["content-type"] = "text/plain; charset=utf-8";
    }

    if (!nextProps.mod.parameters["templates"]) {
      nextProps.mod.parameters["templates"] = {};
    }

    if (!nextProps.mod.parameters["templates"][i18next.language]) {
      nextProps.mod.parameters["templates"][i18next.language] = {
        subject: nextProps.mod.parameters.subject||"Confirm registration", 
        "body-pattern": nextProps.mod.parameters["body-pattern"]||"The code is {CODE}\n\n"+window.location.href.split('?')[0].split('#')[0]+"/"+this.state.config.ProfileUrl+"?register=<your_registration_plugin_name>&token={TOKEN}", 
        defaultLang: true
      };
    }

    if (nextProps.mod.parameters["update-email"] === undefined) {
      nextProps.mod.parameters["update-email"] = false;
    }

    if (!nextProps.mod.parameters["update-email-content-type"]) {
      nextProps.mod.parameters["update-email-content-type"] = "text/plain; charset=utf-8";
    }

    if (!nextProps.mod.parameters["templatesUpdateEmail"]) {
      nextProps.mod.parameters["templatesUpdateEmail"] = {};
    }

    if (!nextProps.mod.parameters["templatesUpdateEmail"][i18next.language]) {
      nextProps.mod.parameters["templatesUpdateEmail"][i18next.language] = {
        subject: "Update e-mail address", 
        "body-pattern": "Click on the following link: "+window.location.href.split('?')[0].split('#')[0]+"/"+this.state.config.ProfileUrl+"?updateEmail=<your_registration_plugin_name>&token={TOKEN}", 
        defaultLang: true
      };
    }

    if (!nextProps.mod.parameters["update-email-token-duration"]) {
      nextProps.mod.parameters["update-email-token-duration"] = 600;
    }
    
    if (!nextProps.mod.parameters["update-email-from"]) {
      nextProps.mod.parameters["update-email-from"] = "";
    }

    if (nextProps.mod.parameters["reset-credentials"] === undefined) {
      nextProps.mod.parameters["reset-credentials"] = false;
    }

    if (!nextProps.mod.parameters["reset-credentials-session-key"]) {
      nextProps.mod.parameters["reset-credentials-session-key"] = "G_CREDENTIALS_SESSION";
    }

    if (!nextProps.mod.parameters["reset-credentials-session-duration"]) {
      nextProps.mod.parameters["reset-credentials-session-duration"] = 3600;
    }

    if (nextProps.mod.parameters["reset-credentials-email"] === undefined) {
      nextProps.mod.parameters["reset-credentials-email"] = false;
    }

    if (!nextProps.mod.parameters["reset-credentials-content-type"]) {
      nextProps.mod.parameters["reset-credentials-content-type"] = "text/plain; charset=utf-8";
    }

    if (!nextProps.mod.parameters["templatesResetCredentials"]) {
      nextProps.mod.parameters["templatesResetCredentials"] = {};
    }

    if (!nextProps.mod.parameters["templatesResetCredentials"][i18next.language]) {
      nextProps.mod.parameters["templatesResetCredentials"][i18next.language] = {
        subject: "Lost credentials", 
        "body-pattern": "Click on the following link: "+window.location.href.split('?')[0].split('#')[0]+"/"+this.state.config.ProfileUrl+"?resetCredentials=<your_registration_plugin_name>&token={TOKEN}", 
        defaultLang: true
      };
    }

    if (!nextProps.mod.parameters["reset-credentials-token-duration"]) {
      nextProps.mod.parameters["reset-credentials-token-duration"] = 600;
    }
    
    if (!nextProps.mod.parameters["reset-credentials-from"]) {
      nextProps.mod.parameters["reset-credentials-from"] = "";
    }

    if (nextProps.mod.parameters["reset-credentials-code"] === undefined) {
      nextProps.mod.parameters["reset-credentials-code"] = false;
    }
    
    if (!nextProps.mod.parameters["reset-credentials-code-list-size"]) {
      nextProps.mod.parameters["reset-credentials-code-list-size"] = 4;
    }

    if (!nextProps.mod.parameters["reset-credentials-code-property"]) {
      nextProps.mod.parameters["reset-credentials-code-property"] = "reset-credentials-code";
    }

    this.setState({
      config: nextProps.config,
      modSchemes: nextProps.modSchemes,
      mod: nextProps.mod,
      role: nextProps.role,
      check: nextProps.check,
      hasError: false,
      currentLang: i18next.language,
      newLang: "",
      currentLangUpdateEmail: i18next.language,
      newLangUpdateEmail: "",
      currentLangResetCredentials: i18next.language,
      newLangResetCredentials: ""
    }, () => {
      if (this.state.check) {
        this.checkParameters();
      }
    });
  }
  
  changeParam(e, param, number) {
    var mod = this.state.mod;
    if (number) {
      if (!isNaN(e.target.value)) {
        mod.parameters[param] = parseInt(e.target.value);
      }
    } else {
      mod.parameters[param] = e.target.value;
    }
    this.setState({mod: mod});
  }
  
  toggleParam(e, param) {
    var mod = this.state.mod;
    mod.parameters[param] = !mod.parameters[param];
    this.setState({mod: mod});
  }

  addScope(e, scope) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["scope"].push(scope);
    this.setState({mod: mod});
  }

  deleteScope(e, index) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["scope"].splice(index, 1);
    this.setState({mod: mod});
  }
  
  setPassword(e, value) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["set-password"] = value;
    this.setState({mod: mod});
  }
  
  addScheme() {
    var added = false;
    var mod = this.state.mod;
    this.state.modSchemes.forEach((schemeMod, indexMod) => {
      var used = false;
      this.state.mod.parameters["schemes"].forEach(curScheme => {
        if (schemeMod.name === curScheme["name"]) {
          used = true;
        }
      });
      if (!used && !added) {
        mod.parameters["schemes"].push({
          "module": schemeMod.module,
          "name": schemeMod.name,
          "display_name": schemeMod.display_name,
          "register": "yes"
        });
        added = true;
      }
    });
    this.setState({mod: mod});
  }
  
  deleteScheme(index) {
    var mod = this.state.mod;
    mod.parameters["schemes"].splice(index, 1);
    this.setState({mod: mod});
  }
  
  setSchemeName(e, index, name) {
    e.preventDefault();
    var mod = this.state.mod;
    this.state.modSchemes.forEach(scheme => {
      if (scheme.name === name) {
        mod.parameters["schemes"][index]["module"] = scheme.module;
        mod.parameters["schemes"][index]["name"] = scheme.name;
        mod.parameters["schemes"][index]["display_name"] = scheme.display_name;
      }
    });
    this.setState({mod: mod});
  }
  
  setSchemeRegister(e, index, register) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["schemes"][index]["register"] = register;
    this.setState({mod: mod});
  }
  
  changeNewLang(e, property = "") {
    var newState = {};
    newState["newLang"+property] = e.target.value;
    this.setState(newState);
  }
  
  addLang(e, property = "") {
    var mod = this.state.mod;
    var found = false;
    var templates = mod.parameters["templates"+property];
    Object.keys(templates).forEach(lang => {
      if (lang === this.state.newLang) {
        found = true;
      }
    });
    if (!found && this.state["newLang"+property]) {
      templates[this.state["newLang"+property]] = {subject: "", "body-pattern": "", defaultLang: false};
      var newState = {mod: mod};
      newState["newLang"+property] = "";
      newState["currentLang"+property] = this.state["newLang"+property];
      this.setState(newState);
    }
  }
  
  removeLang(lang, property = "") {
    var mod = this.state.mod;
    var currentLang = false;
    var templates = mod.parameters["templates"+property];
    delete(templates[lang]);
    if (lang == this.state["currentLang"+property]) {
      Object.keys(templates).forEach(lang => {
        if (!currentLang) {
          currentLang = lang;
        }
      });
      var newState = {mod: mod};
      newState["currentLang"+property] = currentLang;
      this.setState(newState);
    } else {
      this.setState({mod: mod});
    }
  }
  
  changeLang(e, lang, property = "") {
    var mod = this.state.mod;
    var templates = mod.parameters["templates"+property];
    if (!templates[lang]) {
      templates[lang] = {subject: "", "body-pattern": "", defaultLang: false}
    }
    var newState = {};
    newState["currentLang"+property] = lang;
    this.setState(newState);
  }
  
  changeTemplate(e, param, property = "") {
    var mod = this.state.mod;
    var templates = mod.parameters["templates"+property];
    templates[this.state["currentLang"+property]][param] = e.target.value;
    this.setState({mod: mod});
  }
  
  toggleLangDefault(property = "") {
    var mod = this.state.mod;
    var templates = mod.parameters["templates"+property];
    Object.keys(templates).forEach(objKey => {
      templates[objKey].defaultLang = (objKey === this.state["currentLang"+property]);
    });
    this.setState({mod: mod});
  }
  
  checkParameters() {
    var errorList = {}, hasError = false, hasMandatory = false;
    if (this.state.mod.parameters["register"]) {
      if (!this.state.mod.parameters["session-key"]) {
        hasError = true;
        errorList["session-key"] = i18next.t("admin.mod-register-session-key-error");
        errorList["registration"] = true;
      }
      if (!this.state.mod.parameters["session-duration"]) {
        hasError = true;
        errorList["session-duration"] = i18next.t("admin.mod-register-session-duration-error");
        errorList["registration"] = true;
      }
      if (!this.state.mod.parameters.scope.length) {
        hasError = true;
        errorList["scope"] = i18next.t("admin.mod-register-scope-error");
        errorList["registration"] = true;
      }
      this.state.mod.parameters["schemes"].forEach((scheme) => {
        if (!scheme.name) {
          hasError = true;
          errorList["schemes"] = i18next.t("admin.mod-register-scheme-error");
          errorList["registration"] = true;
        }
        if (scheme.register === "always") {
          hasMandatory = true;
        }
      });
      if (this.state.mod.parameters["verify-email"]) {
        if (!this.state.mod.parameters["verification-code-length"]) {
          hasError = true;
          errorList["verification-code-length"] = i18next.t("admin.mod-register-verification-code-length-error");
          errorList["registration"] = true;
        }
        if (!this.state.mod.parameters["verification-code-duration"]) {
          hasError = true;
          errorList["verification-code-duration"] = i18next.t("admin.mod-register-verification-code-duration-error");
          errorList["registration"] = true;
        }
        if (!this.state.mod.parameters["host"]) {
          hasError = true;
          errorList["host"] = i18next.t("admin.mod-email-host-error");
          errorList["smtp"] = true;
        }
        if (!this.state.mod.parameters["from"]) {
          hasError = true;
          errorList["from"] = i18next.t("admin.mod-email-from-error");
          errorList["smtp"] = true;
        }
        errorList["subject"] = "";
        errorList["body-pattern"] = "";
        Object.keys(this.state.mod.parameters.templates).forEach(lang => {
          if (!this.state.mod.parameters.templates[lang]["subject"]) {
            hasError = true;
            errorList["subject"] += i18next.t("admin.mod-email-subject-error", {lang: lang});
            errorList["registration"] = true;
          }
          if (!this.state.mod.parameters.templates[lang]["body-pattern"] || !this.state.mod.parameters.templates[lang]["body-pattern"].search("{CODE}")) {
            hasError = true;
            errorList["body-pattern"] += i18next.t("admin.mod-email-body-pattern-error", {lang: lang});
            errorList["registration"] = true;
          }
        });
      }
      if (this.state.mod.parameters["set-password"] !== "always" && !hasMandatory) {
        hasError = true;
        errorList["has-mandatory"] = i18next.t("admin.mod-register-has-mandatory-error");
        errorList["update-email"] = true;
      }
    }
    if (this.state.mod.parameters["update-email"]) {
      if (!this.state.mod.parameters["update-email-token-duration"]) {
        hasError = true;
        errorList["update-email-token-duration"] = i18next.t("admin.mod-register-update-email-token-duration-error");
        errorList["update-email"] = true;
      }
      if (!this.state.mod.parameters["host"]) {
        hasError = true;
        errorList["host"] = i18next.t("admin.mod-email-host-error");
        errorList["smtp"] = true;
      }
      if (!this.state.mod.parameters["update-email-from"]) {
        hasError = true;
        errorList["update-email-from"] = i18next.t("admin.mod-email-from-error");
        errorList["update-email"] = true;
      }
      errorList["update-email-subject"] = "";
      errorList["update-email-body-pattern"] = "";
      Object.keys(this.state.mod.parameters.templatesUpdateEmail).forEach(lang => {
        if (!this.state.mod.parameters.templatesUpdateEmail[lang]["subject"]) {
          hasError = true;
          errorList["update-email-subject"] += i18next.t("admin.mod-email-subject-error", {lang: lang});
          errorList["update-email"] = true;
        }
        if (!this.state.mod.parameters.templatesUpdateEmail[lang]["body-pattern"] || !this.state.mod.parameters.templatesUpdateEmail[lang]["body-pattern"].search("{TOKEN}")) {
          hasError = true;
          errorList["update-email-body-pattern"] += i18next.t("admin.mod-email-body-pattern-error", {lang: lang});
          errorList["update-email"] = true;
        }
      });
    }
    if (this.state.mod.parameters["reset-credentials"]) {
      if (!this.state.mod.parameters["reset-credentials-session-key"]) {
        hasError = true;
        errorList["reset-credentials-session-key"] = i18next.t("admin.mod-register-reset-credentials-session-key-error");
        errorList["reset-credentials"] = true;
      }
      if (!this.state.mod.parameters["reset-credentials-session-duration"]) {
        hasError = true;
        errorList["reset-credentials-session-duration"] = i18next.t("admin.mod-register-reset-credentials-session-duration-error");
        errorList["reset-credentials"] = true;
      }
      if (this.state.mod.parameters["reset-credentials-email"]) {
        if (!this.state.mod.parameters["reset-credentials-token-duration"]) {
          hasError = true;
          errorList["reset-credentials-token-duration"] = i18next.t("admin.mod-register-reset-credentials-token-duration-error");
          errorList["reset-credentials"] = true;
        }
        if (!this.state.mod.parameters["host"]) {
          hasError = true;
          errorList["host"] = i18next.t("admin.mod-email-host-error");
          errorList["smtp"] = true;
        }
        if (!this.state.mod.parameters["reset-credentials-from"]) {
          hasError = true;
          errorList["reset-credentials-from"] = i18next.t("admin.mod-email-from-error");
          errorList["reset-credentials"] = true;
        }
        errorList["reset-credentials-subject"] = "";
        errorList["reset-credentials-body-pattern"] = "";
        Object.keys(this.state.mod.parameters.templatesResetCredentials).forEach(lang => {
          if (!this.state.mod.parameters.templatesResetCredentials[lang]["subject"]) {
            hasError = true;
            errorList["reset-credentials-subject"] += i18next.t("admin.mod-email-subject-error", {lang: lang});
            errorList["reset-credentials"] = true;
          }
          if (!this.state.mod.parameters.templatesResetCredentials[lang]["body-pattern"] || !this.state.mod.parameters.templatesResetCredentials[lang]["body-pattern"].search("{TOKEN}")) {
            hasError = true;
            errorList["reset-credentials-body-pattern"] += i18next.t("admin.mod-email-body-pattern-error", {lang: lang});
            errorList["reset-credentials"] = true;
          }
        });
      }
      if (this.state.mod.parameters["reset-credentials-code"]) {
        if (!this.state.mod.parameters["reset-credentials-code-property"]) {
          hasError = true;
          errorList["reset-credentials-code-property"] = i18next.t("admin.reset-credentials-code-property-error");
          errorList["reset-credentials"] = true;
        }
      }
      if (!this.state.mod.parameters["reset-credentials-email"] && !this.state.mod.parameters["reset-credentials-code"]) {
        hasError = true;
        errorList["reset-credentials"] = true;
        errorList["reset-credentials-option-check"] = i18next.t("admin.mod-register-option-error");
      }
    }
    if (!this.state.mod.parameters["registration"] && !this.state.mod.parameters["update-email"] && !this.state.mod.parameters["reset-credentials"]) {
      hasError = true;
      errorList["registration"] = true;
      errorList["registration-check"] = i18next.t("admin.mod-register-option-error");
      errorList["update-email"] = true;
      errorList["update-email-check"] = i18next.t("admin.mod-register-option-error");
      errorList["reset-credentials"] = true;
      errorList["reset-credentials-check"] = i18next.t("admin.mod-register-option-error");
    }
    if (!hasError) {
      this.setState({errorList: {}}, () => {
         messageDispatcher.sendMessage('ModPlugin', {type: "modValid"});
      });
    } else {
      this.setState({errorList: errorList}, () => {
        messageDispatcher.sendMessage('ModPlugin', {type: "modInvalid"});
      });
    }
  }
  
  render() {
    var langList = [], langListUpdateEmail = [], langListResetCredentials = [];
    langList.push(
    <div key={-2} className="form-group">
      <div className="input-group mb-3">
        <input type="text" className="form-control" id="mod-email-new-lang" placeholder={i18next.t("admin.mod-email-new-lang-ph")} value={this.state.newLang} onChange={(e) => this.changeNewLang(e)} />
        <div className="input-group-append">
          <button type="button" onClick={(e) => this.addLang(e)} className="btn btn-outline-primary">{i18next.t("admin.mod-email-new-lang-add")}</button>
        </div>
      </div>
    </div>
    );
    langList.push(<div key={-1} className="dropdown-divider"></div>);
    Object.keys(this.state.mod.parameters.templates).forEach((lang, index) => {
      langList.push(
      <div key={index*2} className="btn-group btn-group-justified">
        <button type="button" className="btn btn-primary" disabled={true}>{lang}</button>
        <button type="button" onClick={(e) => this.removeLang(lang)} className="btn btn-primary" disabled={this.state.mod.parameters.templates[lang].defaultLang}>{i18next.t("admin.mod-email-new-lang-remove")}</button>
        <button type="button" onClick={(e) => this.changeLang(e, lang)} className="btn btn-primary">{i18next.t("admin.mod-email-new-lang-select")}</button>
      </div>
      );
      langList.push(<div key={(index*2)+1} className="dropdown-divider"></div>);
    });
    langListUpdateEmail.push(
    <div key={-2} className="form-group">
      <div className="input-group mb-3">
        <input type="text" className="form-control" id="mod-email-new-lang" placeholder={i18next.t("admin.mod-email-new-lang-ph")} value={this.state.newLangUpdateEmail} onChange={(e) => this.changeNewLang(e, "UpdateEmail")} />
        <div className="input-group-append">
          <button type="button" onClick={(e) => this.addLang(e, "UpdateEmail")} className="btn btn-outline-primary">{i18next.t("admin.mod-email-new-lang-add")}</button>
        </div>
      </div>
    </div>
    );
    langListUpdateEmail.push(<div key={-1} className="dropdown-divider"></div>);
    Object.keys(this.state.mod.parameters.templatesUpdateEmail).forEach((lang, index) => {
      langListUpdateEmail.push(
      <div key={index*2} className="btn-group btn-group-justified">
        <button type="button" className="btn btn-primary" disabled={true}>{lang}</button>
        <button type="button" onClick={(e) => this.removeLang(lang, "UpdateEmail")} className="btn btn-primary" disabled={this.state.mod.parameters.templatesUpdateEmail[lang].defaultLang}>{i18next.t("admin.mod-email-new-lang-remove")}</button>
        <button type="button" onClick={(e) => this.changeLang(e, lang, "UpdateEmail")} className="btn btn-primary">{i18next.t("admin.mod-email-new-lang-select")}</button>
      </div>
      );
      langListUpdateEmail.push(<div key={(index*2)+1} className="dropdown-divider"></div>);
    });
    langListResetCredentials.push(
    <div key={-2} className="form-group">
      <div className="input-group mb-3">
        <input type="text" className="form-control" id="mod-email-new-lang" placeholder={i18next.t("admin.mod-email-new-lang-ph")} value={this.state.newLangResetCredentials} onChange={(e) => this.changeNewLang(e, "ResetCredentials")} />
        <div className="input-group-append">
          <button type="button" onClick={(e) => this.addLang(e, "ResetCredentials")} className="btn btn-outline-primary">{i18next.t("admin.mod-email-new-lang-add")}</button>
        </div>
      </div>
    </div>
    );
    langListResetCredentials.push(<div key={-1} className="dropdown-divider"></div>);
    Object.keys(this.state.mod.parameters.templatesResetCredentials).forEach((lang, index) => {
      langListResetCredentials.push(
      <div key={index*2} className="btn-group btn-group-justified">
        <button type="button" className="btn btn-primary" disabled={true}>{lang}</button>
        <button type="button" onClick={(e) => this.removeLang(lang, "ResetCredentials")} className="btn btn-primary" disabled={this.state.mod.parameters.templatesResetCredentials[lang].defaultLang}>{i18next.t("admin.mod-email-new-lang-remove")}</button>
        <button type="button" onClick={(e) => this.changeLang(e, lang, "ResetCredentials")} className="btn btn-primary">{i18next.t("admin.mod-email-new-lang-select")}</button>
      </div>
      );
      langListResetCredentials.push(<div key={(index*2)+1} className="dropdown-divider"></div>);
    });
    var scopeList = [], defaultScopeList = [], schemeList = [];
    this.state.config.pattern.user.forEach((pattern) => {
      if (pattern.name === "scope") {
        pattern.listElements.forEach((scope, index) => {
          scopeList.push(<a key={index} className="dropdown-item" href="#" onClick={(e) => this.addScope(e, scope)}>{scope}</a>);
        })
      }
    });
    this.state.mod.parameters["scope"].forEach((scope, index) => {
      defaultScopeList.push(<a className="btn-icon-right" href="#" onClick={(e) => this.deleteScope(e, index)} key={index}><span className="badge badge-primary">{scope}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>);
    });
    var scopeJsx = 
    <div className="dropdown">
      <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-register-scope" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">{i18next.t("admin.mod-register-scope")}</button>
      <div className="dropdown-menu" aria-labelledby="mod-register-scope">
        {scopeList}
      </div>
      <div>
        {defaultScopeList}
      </div>
    </div>;
    this.state.mod.parameters["schemes"].forEach((scheme, index) => {
      var schemeModList = [];
      this.state.modSchemes.forEach((schemeMod, indexMod) => {
        var used = false;
        this.state.mod.parameters["schemes"].forEach(curScheme => {
          if (schemeMod.name === curScheme["name"]) {
            used = true;
          }
        });
        if (!used) {
          schemeModList.push(<a key={indexMod} className="dropdown-item" href="#" onClick={(e) => this.setSchemeName(e, index, schemeMod.name)}>{schemeMod.display_name}</a>);
        }
      });
      schemeList.push(
        <div className="form-group" key={index}>
          <div className="input-group mb-3">
            <label className="input-group-text" htmlFor={"mod-register-name-"+index}>{i18next.t("admin.mod-register-scheme-name")}</label>
            <div className="input-group-append">
              <div className="dropdown">
                <button className="btn btn-secondary dropdown-toggle" type="button" id={"mod-register-name-"+index} data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                  {scheme["display_name"]}
                </button>
                <div className="dropdown-menu" aria-labelledby="mod-register-name">
                  {schemeModList}
                </div>
              </div>
            </div>
            <label className="input-group-text btn-icon-left" htmlFor={"mod-register-scheme-register-"+index}>{i18next.t("admin.mod-register-scheme-register")}</label>
            <div className="input-group-append">
              <div className="dropdown">
                <button className="btn btn-secondary dropdown-toggle" type="button" id={"mod-register-scheme-register-"+index} data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                  {i18next.t("admin.mod-register-"+(scheme["register"]==="always"?"yes":"no"))}
                </button>
                <div className="dropdown-menu" aria-labelledby="mod-register-scheme-register">
                  <a className={"dropdown-item"+(scheme["register"]==="always"?" active":"")} href="#" onClick={(e) => this.setSchemeRegister(e, index, "always")}>{i18next.t("admin.mod-register-yes")}</a>
                  <a className={"dropdown-item"+(scheme["register"]==="yes"?" active":"")} href="#" onClick={(e) => this.setSchemeRegister(e, index, "yes")}>{i18next.t("admin.mod-register-no")}</a>
                </div>
              </div>
            </div>
            <button className="btn btn-secondary btn-icon-right" type="button" onClick={() => this.deleteScheme(index)}>
              <i className="fas fa-trash"></i>
            </button>
          </div>
        </div>
      );
    });

    return (
      <div>
        <div className="accordion" id="accordionRegister">
          <div className="card">
            <div className="card-header" id="registerCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseRegister" aria-expanded="true" aria-controls="collapseRegister">
                  {this.state.errorList["registration"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-register-title")}
                </button>
              </h2>
            </div>
            <div id="collapseRegister" className="collapse" aria-labelledby="registerCard" data-parent="#accordionRegister">
              <div className="card-body">
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-register-enabled" onChange={(e) => this.toggleParam(e, "registration")} checked={this.state.mod.parameters["registration"]} />
                  <label className="form-check-label" htmlFor="mod-register-enabled">{i18next.t("admin.mod-register-enabled")}</label>
                  {this.state.errorList["registration-check"]?<div><span className="error-input">{this.state.errorList["registration-check"]}</span></div>:""}
                </div>
                <div className={"collapse"+(this.state.mod.parameters["registration"]?" show":"")} id="registerCollapse">
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-register-session-key">{i18next.t("admin.mod-register-session-key")}</label>
                      </div>
                      <input type="text" className={this.state.errorList["session-key"]?"form-control is-invalid":"form-control"} id="mod-register-session-key" onChange={(e) => this.changeParam(e, "session-key")} value={this.state.mod.parameters["session-key"]} placeholder={i18next.t("admin.mod-register-session-key-ph")} />
                    </div>
                    {this.state.errorList["session-key"]?<span className="error-input">{this.state.errorList["session-key"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-register-session-duration">{i18next.t("admin.mod-register-session-duration")}</label>
                      </div>
                      <input type="number" min="1" step="1" className={this.state.errorList["session-duration"]?"form-control is-invalid":"form-control"} id="mod-register-session-duration" onChange={(e) => this.changeParam(e, "session-duration", true)} value={this.state.mod.parameters["session-duration"]} placeholder={i18next.t("admin.mod-register-session-duration-ph")} />
                    </div>
                    {this.state.errorList["session-duration"]?<span className="error-input">{this.state.errorList["session-duration"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-register-set-password">{i18next.t("admin.mod-register-set-password")}</label>
                      </div>
                      <div className="dropdown">
                        <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-register-set-password" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                          {i18next.t("admin.mod-register-"+this.state.mod.parameters["set-password"])}
                        </button>
                        <div className="dropdown-menu" aria-labelledby="mod-register-set-password">
                          <a className={"dropdown-item"+(this.state.mod.parameters["set-password"]==="always"?" active":"")} href="#" onClick={(e) => this.setPassword(e, "always")}>{i18next.t("admin.mod-register-always")}</a>
                          <a className={"dropdown-item"+(this.state.mod.parameters["set-password"]==="yes"?" active":"")} href="#" onClick={(e) => this.setPassword(e, "yes")}>{i18next.t("admin.mod-register-yes")}</a>
                          <a className={"dropdown-item"+(this.state.mod.parameters["set-password"]==="no"?" active":"")} href="#" onClick={(e) => this.setPassword(e, "no")}>{i18next.t("admin.mod-register-no")}</a>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-default-scope">{i18next.t("admin.mod-register-scope-add")}</label>
                      </div>
                      {scopeJsx}
                    </div>
                    {this.state.errorList["scope"]?<span className="error-input">{this.state.errorList["scope"]}</span>:""}
                  </div>
                  <hr/>
                  <div className="form-group">
                    <button type="button" className="btn btn-secondary" onClick={this.addScheme} disabled={this.state.mod.parameters["schemes"].length===this.state.modSchemes.length}>
                      {i18next.t("admin.mod-register-add-scheme")}
                    </button>
                  </div>
                  {schemeList}
                  {this.state.errorList["schemes"]?<span className="error-input">{this.state.errorList["schemes"]}</span>:""}
                  <hr/>
                  <div className="form-group form-check">
                    <input type="checkbox" className="form-check-input" id="mod-register-verify-email" onChange={(e) => this.toggleParam(e, "verify-email")} checked={this.state.mod.parameters["verify-email"]} />
                    <label className="form-check-label" htmlFor="mod-register-verify-email">{i18next.t("admin.mod-register-verify-email")}</label>
                  </div>
                  <div className={"collapse"+(this.state.mod.parameters["verify-email"]?" show":"")} id="verifyEmailCollapse">
                    <div className="form-group form-check">
                      <input type="checkbox" disabled={!this.state.mod.parameters["verify-email"]} className="form-check-input" id="mod-register-email-is-username" onChange={(e) => this.toggleParam(e, "email-is-username")} checked={this.state.mod.parameters["email-is-username"]} />
                      <label className="form-check-label" htmlFor="mod-register-email-is-username">{i18next.t("admin.mod-register-email-is-username")}</label>
                    </div>
                    <div className="form-group">
                      <div className="input-group mb-3">
                        <div className="input-group-prepend">
                          <label className="input-group-text" htmlFor="mod-register-verification-code-length">{i18next.t("admin.mod-register-verification-code-length")}</label>
                        </div>
                        <input type="number" min="0" max="65536" step="1" className={this.state.errorList["verification-code-length"]?"form-control is-invalid":"form-control"} id="mod-register-verification-code-length" onChange={(e) => this.changeParam(e, "verification-code-length")} value={this.state.mod.parameters["verification-code-length"]} placeholder={i18next.t("admin.mod-register-verification-code-length-ph")} />
                      </div>
                      {this.state.errorList["verification-code-length"]?<span className="error-input">{this.state.errorList["verification-code-length"]}</span>:""}
                    </div>
                    <div className="form-group">
                      <div className="input-group mb-3">
                        <div className="input-group-prepend">
                          <label className="input-group-text" htmlFor="mod-register-verification-code-duration">{i18next.t("admin.mod-register-verification-code-duration")}</label>
                        </div>
                        <input type="number" min="0" max="65536" step="1" className={this.state.errorList["verification-code-duration"]?"form-control is-invalid":"form-control"} id="mod-register-verification-code-duration" onChange={(e) => this.changeParam(e, "verification-code-duration", true)} value={this.state.mod.parameters["verification-code-duration"]} placeholder={i18next.t("admin.mod-register-verification-code-duration-ph")} />
                      </div>
                      {this.state.errorList["verification-code-duration"]?<span className="error-input">{this.state.errorList["verification-code-duration"]}</span>:""}
                    </div>
                    <hr/>
                    <div className="form-group">
                      <div className="input-group mb-3">
                        <div className="input-group-prepend">
                          <label className="input-group-text" htmlFor="mod-register-from">{i18next.t("admin.mod-email-from")}</label>
                        </div>
                        <input type="text" className={this.state.errorList["from"]?"form-control is-invalid":"form-control"} id="mod-register-from" onChange={(e) => this.changeParam(e, "from")} value={this.state.mod.parameters["from"]} placeholder={i18next.t("admin.mod-email-from-ph")} />
                      </div>
                      {this.state.errorList["from"]?<span className="error-input">{this.state.errorList["from"]}</span>:""}
                    </div>
                    <div className="form-group">
                      <div className="input-group mb-3">
                        <div className="input-group-prepend">
                          <label className="input-group-text" htmlFor="mod-register-content-type">{i18next.t("admin.mod-email-content-type")}</label>
                        </div>
                        <input type="text" className={this.state.errorList["content-type"]?"form-control is-invalid":"form-control"} id="mod-register-content-type" onChange={(e) => this.changeParam(e, "content-type")} value={this.state.mod.parameters["content-type"]||""} placeholder={i18next.t("admin.mod-email-content-type-ph")} />
                      </div>
                      {this.state.errorList["content-type"]?<span className="error-input">{this.state.errorList["content-type"]}</span>:""}
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
                      <input type="checkbox" className="form-check-input" id="mod-email-lang-default" onChange={(e) => this.toggleLangDefault()} checked={this.state.mod.parameters.templates[this.state.currentLang].defaultLang} />
                      <label className="form-check-label" htmlFor="mod-email-lang-default">{i18next.t("admin.mod-email-lang-default")}</label>
                    </div>
                    <div className="form-group">
                      <div className="input-group mb-3">
                        <div className="input-group-prepend">
                          <label className="input-group-text" htmlFor="mod-email-subject">{i18next.t("admin.mod-email-subject")}</label>
                        </div>
                        <input type="text" className={this.state.errorList["subject"]?"form-control is-invalid":"form-control"} id="mod-email-subject" onChange={(e) => this.changeTemplate(e, "subject")} value={this.state.mod.parameters.templates[this.state.currentLang]["subject"]} placeholder={i18next.t("admin.mod-email-subject-ph")} />
                      </div>
                      {this.state.errorList["subject"]?<span className="error-input">{this.state.errorList["subject"]}</span>:""}
                    </div>
                    <div className="form-group">
                      <div className="input-group mb-3">
                        <div className="input-group-prepend">
                          <span className="input-group-text" >{i18next.t("admin.mod-email-body-pattern")}</span>
                        </div>
                        <textarea className={this.state.errorList["body-pattern"]?"form-control is-invalid":"form-control"} id="mod-email-body-pattern" onChange={(e) => this.changeTemplate(e, "body-pattern")} placeholder={i18next.t("admin.mod-email-body-pattern-ph")} value={this.state.mod.parameters.templates[this.state.currentLang]["body-pattern"]}></textarea>
                      </div>
                      {this.state.errorList["body-pattern"]?<span className="error-input">{this.state.errorList["body-pattern"]}</span>:""}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionUpdateEmail">
          <div className="card">
            <div className="card-header" id="updateEmailCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseUpdateEmail" aria-expanded="true" aria-controls="collapseUpdateEmail">
                  {this.state.errorList["update-email"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-register-update-email-title")}
                </button>
              </h2>
            </div>
            <div id="collapseUpdateEmail" className="collapse" aria-labelledby="updateEmailCard" data-parent="#accordionUpdateEmail">
              <div className="card-body">
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-register-update-email" onChange={(e) => this.toggleParam(e, "update-email")} checked={this.state.mod.parameters["update-email"]} />
                  <label className="form-check-label" htmlFor="mod-register-update-email">{i18next.t("admin.mod-register-update-email")}</label>
                  {this.state.errorList["update-email-check"]?<div><span className="error-input">{this.state.errorList["update-email-check"]}</span></div>:""}
                </div>
                <div className={"collapse"+(this.state.mod.parameters["update-email"]?" show":"")} id="updateEmailCollapse">
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-register-update-email-token-duration">{i18next.t("admin.mod-register-update-email-token-duration")}</label>
                      </div>
                      <input type="number" min="0" max="65536" step="1" className="form-control" id="mod-register-update-email-token-duration" onChange={(e) => this.changeParam(e, "update-email-token-duration", true)} value={this.state.mod.parameters["update-email-token-duration"]} placeholder={i18next.t("admin.mod-register-update-email-token-duration-ph")}/>
                    </div>
                  </div>
                  <hr/>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-update-email-from">{i18next.t("admin.mod-email-from")}</label>
                      </div>
                      <input type="text" className={this.state.errorList["from"]?"form-control is-invalid":"form-control"} id="mod-update-email-update-email-from" onChange={(e) => this.changeParam(e, "update-email-from")} value={this.state.mod.parameters["update-email-from"]} placeholder={i18next.t("admin.mod-email-from-ph")} />
                    </div>
                    {this.state.errorList["update-email-from"]?<span className="error-input">{this.state.errorList["update-email-from"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-update-email-content-type">{i18next.t("admin.mod-email-content-type")}</label>
                      </div>
                      <input type="text" className={this.state.errorList["update-email-content-type"]?"form-control is-invalid":"form-control"} id="mod-update-email-content-type" onChange={(e) => this.changeParam(e, "update-email-content-type")} value={this.state.mod.parameters["update-email-content-type"]||""} placeholder={i18next.t("admin.mod-email-content-type-ph")} />
                    </div>
                    {this.state.errorList["update-email-content-type"]?<span className="error-input">{this.state.errorList["update-email-content-type"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-update-email-email-lang">{i18next.t("admin.mod-email-lang")}</label>
                      </div>
                      <div className="dropdown">
                        <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-update-email-email-lang" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                          {this.state.currentLangUpdateEmail}
                        </button>
                        <div className="dropdown-menu" aria-labelledby="mod-update-email-email-lang">
                          {langListUpdateEmail}
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="form-group form-check">
                    <input type="checkbox" className="form-check-input" id="mod-update-email-email-lang-default" onChange={(e) => this.toggleLangDefault("UpdateEmail")} checked={this.state.mod.parameters.templatesUpdateEmail[this.state.currentLangUpdateEmail].defaultLang} />
                    <label className="form-check-label" htmlFor="mod-update-email-email-lang-default">{i18next.t("admin.mod-email-lang-default")}</label>
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-update-email-email-subject">{i18next.t("admin.mod-email-subject")}</label>
                      </div>
                      <input type="text" className={this.state.errorList["update-email-subject"]?"form-control is-invalid":"form-control"} id="mod-update-email-email-subject" onChange={(e) => this.changeTemplate(e, "subject", "UpdateEmail")} value={this.state.mod.parameters.templatesUpdateEmail[this.state.currentLangUpdateEmail]["subject"]} placeholder={i18next.t("admin.mod-update-email-subject-ph")} />
                    </div>
                    {this.state.errorList["update-email-subject"]?<span className="error-input">{this.state.errorList["update-email-subject"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <span className="input-group-text" >{i18next.t("admin.mod-email-body-pattern-token")}</span>
                      </div>
                      <textarea className={this.state.errorList["update-email-body-pattern"]?"form-control is-invalid":"form-control"} id="mod-update-email-body-pattern" onChange={(e) => this.changeTemplate(e, "body-pattern", "UpdateEmail")} placeholder={i18next.t("admin.mod-email-body-pattern-token-ph")} value={this.state.mod.parameters.templatesUpdateEmail[this.state.currentLangUpdateEmail]["body-pattern"]}></textarea>
                    </div>
                    {this.state.errorList["update-email-body-pattern"]?<span className="error-input">{this.state.errorList["update-email-body-pattern"]}</span>:""}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionResetCredentials">
          <div className="card">
            <div className="card-header" id="resetCredentialsCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseResetCredentials" aria-expanded="true" aria-controls="collapseResetCredentials">
                  {this.state.errorList["reset-credentials"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-register-reset-credentials-title")}
                </button>
              </h2>
            </div>
            <div id="collapseResetCredentials" className="collapse" aria-labelledby="resetCredentialsCard" data-parent="#accordionResetCredentials">
              <div className="card-body">
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-register-reset-credentials" onChange={(e) => this.toggleParam(e, "reset-credentials")} checked={this.state.mod.parameters["reset-credentials"]} />
                  <label className="form-check-label" htmlFor="mod-register-reset-credentials">{i18next.t("admin.mod-register-reset-credentials")}</label>
                  {this.state.errorList["reset-credentials-option-check"]?<div><span className="error-input">{this.state.errorList["reset-credentials-check"]}</span></div>:""}
                </div>
                <div className={"collapse"+(this.state.mod.parameters["reset-credentials"]?" show":"")} id="updateResetCredentials">
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-register-reset-credentials-session-key">{i18next.t("admin.mod-register-reset-credentials-session-key")}</label>
                      </div>
                      <input type="text" className={this.state.errorList["reset-credentials-session-key"]?"form-control is-invalid":"form-control"} id="mod-register-reset-credentials-session-key" onChange={(e) => this.changeParam(e, "reset-credentials-session-key")} value={this.state.mod.parameters["reset-credentials-session-key"]} placeholder={i18next.t("admin.mod-register-reset-credentials-session-key")} />
                    </div>
                    {this.state.errorList["reset-credentials-session-key"]?<span className="error-input">{this.state.errorList["reset-credentials-session-key"]}</span>:""}
                  </div>
                  <div className="form-group">
                    <div className="input-group mb-3">
                      <div className="input-group-prepend">
                        <label className="input-group-text" htmlFor="mod-register-reset-credentials-session-duration">{i18next.t("admin.mod-register-reset-credentials-session-duration")}</label>
                      </div>
                      <input type="number" min="1" step="1" className={this.state.errorList["reset-credentials-session-duration"]?"form-control is-invalid":"form-control"} id="mod-register-reset-credentials-session-duration" onChange={(e) => this.changeParam(e, "reset-credentials-session-duration", true)} value={this.state.mod.parameters["reset-credentials-session-duration"]} placeholder={i18next.t("admin.mod-register-reset-credentials-session-duration-ph")} />
                    </div>
                    {this.state.errorList["reset-credentials-session-duration"]?<span className="error-input">{this.state.errorList["reset-credentials-session-duration"]}</span>:""}
                  </div>
                  <div className="form-group form-check">
                    <input type="checkbox" className="form-check-input" id="mod-register-reset-credentials-email" onChange={(e) => this.toggleParam(e, "reset-credentials-email")} checked={this.state.mod.parameters["reset-credentials-email"]} />
                    <label className="form-check-label" htmlFor="mod-register-reset-credentials-email">{i18next.t("admin.mod-register-reset-credentials-email")}</label>
                    {this.state.errorList["reset-credentials-option-check"]?<div><span className="error-input">{this.state.errorList["reset-credentials-option-check"]}</span></div>:""}
                  </div>
                  <div className={"collapse"+(this.state.mod.parameters["reset-credentials-email"]?" show":"")} id="updateResetCredentialsEmail">
                    <div className="form-group">
                      <div className="input-group mb-3">
                        <div className="input-group-prepend">
                          <label className="input-group-text" htmlFor="mod-register-reset-credentials-token-duration">{i18next.t("admin.mod-register-reset-credentials-token-duration")}</label>
                        </div>
                        <input type="number" min="0" max="65536" step="1" className="form-control" id="mod-register-reset-credentials-token-duration" onChange={(e) => this.changeParam(e, "reset-credentials-token-duration", true)} value={this.state.mod.parameters["reset-credentials-token-duration"]} placeholder={i18next.t("admin.mod-register-reset-credentials-token-duration-ph")}/>
                      </div>
                    </div>
                    <hr/>
                    <div className="form-group">
                      <div className="input-group mb-3">
                        <div className="input-group-prepend">
                          <label className="input-group-text" htmlFor="mod-reset-credentials-from">{i18next.t("admin.mod-email-from")}</label>
                        </div>
                        <input type="text" className={this.state.errorList["from"]?"form-control is-invalid":"form-control"} id="mod-reset-credentials-reset-credentials-from" onChange={(e) => this.changeParam(e, "reset-credentials-from")} value={this.state.mod.parameters["reset-credentials-from"]} placeholder={i18next.t("admin.mod-email-from-ph")} />
                      </div>
                      {this.state.errorList["reset-credentials-from"]?<span className="error-input">{this.state.errorList["reset-credentials-from"]}</span>:""}
                    </div>
                    <div className="form-group">
                      <div className="input-group mb-3">
                        <div className="input-group-prepend">
                          <label className="input-group-text" htmlFor="mod-reset-credentials-content-type">{i18next.t("admin.mod-email-content-type")}</label>
                        </div>
                        <input type="text" className={this.state.errorList["reset-credentials-content-type"]?"form-control is-invalid":"form-control"} id="mod-reset-credentials-content-type" onChange={(e) => this.changeParam(e, "reset-credentials-content-type")} value={this.state.mod.parameters["reset-credentials-content-type"]||""} placeholder={i18next.t("admin.mod-email-content-type-ph")} />
                      </div>
                      {this.state.errorList["reset-credentials-content-type"]?<span className="error-input">{this.state.errorList["reset-credentials-content-type"]}</span>:""}
                    </div>
                    <div className="form-group">
                      <div className="input-group mb-3">
                        <div className="input-group-prepend">
                          <label className="input-group-text" htmlFor="mod-reset-credentials-email-lang">{i18next.t("admin.mod-email-lang")}</label>
                        </div>
                        <div className="dropdown">
                          <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-reset-credentials-email-lang" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                            {this.state.currentLangResetCredentials}
                          </button>
                          <div className="dropdown-menu" aria-labelledby="mod-reset-credentials-email-lang">
                            {langListResetCredentials}
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="form-group form-check">
                      <input type="checkbox" className="form-check-input" id="mod-reset-credentials-email-lang-default" onChange={(e) => this.toggleLangDefault("ResetCredentials")} checked={this.state.mod.parameters.templatesResetCredentials[this.state.currentLangResetCredentials].defaultLang} />
                      <label className="form-check-label" htmlFor="mod-reset-credentials-email-lang-default">{i18next.t("admin.mod-email-lang-default")}</label>
                    </div>
                    <div className="form-group">
                      <div className="input-group mb-3">
                        <div className="input-group-prepend">
                          <label className="input-group-text" htmlFor="mod-reset-credentials-email-subject">{i18next.t("admin.mod-email-subject")}</label>
                        </div>
                        <input type="text" className={this.state.errorList["reset-credentials-subject"]?"form-control is-invalid":"form-control"} id="mod-reset-credentials-email-subject" onChange={(e) => this.changeTemplate(e, "subject", "ResetCredentials")} value={this.state.mod.parameters.templatesResetCredentials[this.state.currentLangResetCredentials]["subject"]} placeholder={i18next.t("admin.mod-reset-credentials-subject-ph")} />
                      </div>
                      {this.state.errorList["reset-credentials-subject"]?<span className="error-input">{this.state.errorList["reset-credentials-subject"]}</span>:""}
                    </div>
                    <div className="form-group">
                      <div className="input-group mb-3">
                        <div className="input-group-prepend">
                          <span className="input-group-text" >{i18next.t("admin.mod-email-body-pattern-token")}</span>
                        </div>
                        <textarea className={this.state.errorList["reset-credentials-body-pattern"]?"form-control is-invalid":"form-control"} id="mod-reset-credentials-body-pattern" onChange={(e) => this.changeTemplate(e, "body-pattern", "ResetCredentials")} placeholder={i18next.t("admin.mod-email-body-pattern-token-ph")} value={this.state.mod.parameters.templatesResetCredentials[this.state.currentLangResetCredentials]["body-pattern"]}></textarea>
                      </div>
                      {this.state.errorList["reset-credentials-body-pattern"]?<span className="error-input">{this.state.errorList["reset-credentials-body-pattern"]}</span>:""}
                    </div>
                  </div>
                  <div className="form-group form-check">
                    <input type="checkbox" className="form-check-input" id="mod-register-reset-credentials-code" onChange={(e) => this.toggleParam(e, "reset-credentials-code")} checked={this.state.mod.parameters["reset-credentials-code"]} />
                    <label className="form-check-label" htmlFor="mod-register-reset-credentials-code">{i18next.t("admin.mod-register-reset-credentials-code")}</label>
                    {this.state.errorList["reset-credentials-option-check"]?<div><span className="error-input">{this.state.errorList["reset-credentials-option-check"]}</span></div>:""}
                  </div>
                  <div className={"collapse"+(this.state.mod.parameters["reset-credentials-code"]?" show":"")} id="updateResetCredentialsCode">
                    <div className="form-group">
                      <div className="input-group mb-3">
                        <div className="input-group-prepend">
                          <label className="input-group-text" htmlFor="mod-register-reset-credentials-code-property">{i18next.t("admin.mod-register-reset-credentials-code-property")}</label>
                        </div>
                        <input type="text" className={this.state.errorList["reset-credentials-code-property"]?"form-control is-invalid":"form-control"} id="mod-register-reset-credentials-code-property" onChange={(e) => this.changeParam(e, "reset-credentials-code-property")} value={this.state.mod.parameters["reset-credentials-code-property"]} placeholder={i18next.t("admin.mod-register-reset-credentials-code-property")} />
                      </div>
                      {this.state.errorList["reset-credentials-code-property"]?<span className="error-input">{this.state.errorList["reset-credentials-code-property"]}</span>:""}
                    </div>
                    <div className="form-group">
                      <div className="input-group mb-3">
                        <div className="input-group-prepend">
                          <label className="input-group-text" htmlFor="mod-reset-credentials-code-list-size">{i18next.t("admin.mod-reset-credentials-code-list-size")}</label>
                        </div>
                        <input type="number" min="1" max="65536" step="1" className="form-control" id="mod-reset-credentials-code-list-size" onChange={(e) => this.changeParam(e, "reset-credentials-code-list-size", true)} value={this.state.mod.parameters["reset-credentials-code-list-size"]} placeholder={i18next.t("admin.mod-reset-credentials-code-list-size-ph")}/>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="accordion" id="accordionSMTPParams">
          <div className="card">
            <div className="card-header" id="SMTPParamsCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseSMTPParams" aria-expanded="true" aria-controls="collapseSMTPParams">
                  {this.state.errorList["smtp"]?<span className="error-input btn-icon"><i className="fas fa-exclamation-circle"></i></span>:""}
                  {i18next.t("admin.mod-register-smtp-params-title")}
                </button>
              </h2>
            </div>
            <div id="collapseSMTPParams" className="collapse" aria-labelledby="SMTPParamsCard" data-parent="#accordionSMTPParams">
              <div className="card-body">
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-register-host">{i18next.t("admin.mod-email-host")}</label>
                    </div>
                    <input type="text" className={this.state.errorList["host"]?"form-control is-invalid":"form-control"} id="mod-register-host" onChange={(e) => this.changeParam(e, "host")} value={this.state.mod.parameters["host"]} placeholder={i18next.t("admin.mod-email-host-ph")} />
                  </div>
                  {this.state.errorList["host"]?<span className="error-input">{this.state.errorList["host"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-register-port">{i18next.t("admin.mod-email-port")}</label>
                    </div>
                    <input type="number" min="0" max="65536" step="1" className={this.state.errorList["port"]?"form-control is-invalid":"form-control"} id="mod-register-port" onChange={(e) => this.changeParam(e, "port", true)} value={this.state.mod.parameters["port"]} placeholder={i18next.t("admin.mod-email-port-ph")} />
                  </div>
                  {this.state.errorList["port"]?<span className="error-input">{this.state.errorList["port"]}</span>:""}
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" id="mod-register-use-tls" onChange={(e) => this.toggleParam(e, "use-tls")} checked={this.state.mod.parameters["use-tls"]||false} />
                  <label className="form-check-label" htmlFor="mod-register-use-tls">{i18next.t("admin.mod-email-use-tls")}</label>
                </div>
                <div className="form-group form-check">
                  <input type="checkbox" className="form-check-input" disabled={!this.state.mod.parameters["use-tls"]} id="mod-register-check-certificate" onChange={(e) => this.toggleParam(e, "check-certificate")} checked={this.state.mod.parameters["check-certificate"]||false} />
                  <label className="form-check-label" htmlFor="mod-register-check-certificate">{i18next.t("admin.mod-email-check-certificate")}</label>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-register-user">{i18next.t("admin.mod-email-user")}</label>
                    </div>
                    <input type="text" className={this.state.errorList["user"]?"form-control is-invalid":"form-control"} id="mod-register-user" onChange={(e) => this.changeParam(e, "user")} value={this.state.mod.parameters["user"]} placeholder={i18next.t("admin.mod-email-user-ph")} />
                  </div>
                  {this.state.errorList["user"]?<span className="error-input">{this.state.errorList["user"]}</span>:""}
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-register-password">{i18next.t("admin.mod-email-password")}</label>
                    </div>
                    <input type="password" className={this.state.errorList["password"]?"form-control is-invalid":"form-control"} id="mod-register-password" onChange={(e) => this.changeParam(e, "password")} value={this.state.mod.parameters["password"]} placeholder={i18next.t("admin.mod-email-password-ph")} />
                  </div>
                  {this.state.errorList["password"]?<span className="error-input">{this.state.errorList["password"]}</span>:""}
                </div>
              </div>
            </div>
          </div>
        </div>
        {this.state.errorList["has-mandatory"]?<span className="error-input">{this.state.errorList["has-mandatory"]}</span>:""}
      </div>
    );
  }
}

export default RegisterParams;
