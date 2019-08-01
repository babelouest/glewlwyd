import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class LDAPParams extends Component {
  constructor(props) {
    super(props);
    
    if (!props.mod.parameters["scope-match"]) {
      props.mod.parameters["scope-match"] = [];
    }
    
    if (!props.mod.parameters["search-scope"]) {
      props.mod.parameters["search-scope"] = "one";
    }
    
    this.state = {
      mod: props.mod,
      role: props.role,
      check: props.check,
      errorList: {}
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.addDataFormat = this.addDataFormat.bind(this);
    this.changeDataFormatProperty = this.changeDataFormatProperty.bind(this);
    this.changeDataFormatLdapProperty = this.changeDataFormatLdapProperty.bind(this);
    this.toggleDataFormatValue = this.toggleDataFormatValue.bind(this);
    this.toggleDataFormatMultiple = this.toggleDataFormatMultiple.bind(this);
    this.deleteDataFormat = this.deleteDataFormat.bind(this);
    this.changeParam = this.changeParam.bind(this);
    this.addScopeMatch = this.addScopeMatch.bind(this);
    this.changeScopeMatchProperty = this.changeScopeMatchProperty.bind(this);
    this.changeMatchType = this.changeMatchType.bind(this);
    this.changePasswordAlgorithm = this.changePasswordAlgorithm.bind(this);
    this.getMatchType = this.getMatchType.bind(this);
    this.changePageSize = this.changePageSize.bind(this);
    this.checkParameters = this.checkParameters.bind(this);
    this.deleteScopeMatch = this.deleteScopeMatch.bind(this);
    this.changeSearchScope = this.changeSearchScope.bind(this);
    this.changeConfidential = this.changeConfidential.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    
    if (!nextProps.mod.parameters["scope-match"]) {
      nextProps.mod.parameters["scope-match"] = [];
    }
    
    if (!nextProps.mod.parameters["search-scope"]) {
      nextProps.mod.parameters["search-scope"] = "one";
    }
    
    this.setState({
      mod: nextProps.mod,
      role: nextProps.role,
      check: nextProps.check
    }, () => {
      if (this.state.check) {
        this.checkParameters();
      }
    });
  }
  
  addDataFormat() {
    var mod = this.state.mod;
    if (!mod.parameters["data-format"]) {
      mod.parameters["data-format"] = {};
    }
    mod.parameters["data-format"][""] = {property: "", multiple: false, read: true, write: true, "profile-read": false, "profile-write": false};
    this.setState({mod: mod});
  }
  
  changeDataFormatProperty(e, property) {
    var mod = this.state.mod;
    mod.parameters["data-format"][e.target.value] = mod.parameters["data-format"][property];
    delete(mod.parameters["data-format"][property]);
    this.setState({mod: mod});
  }
  
  changeDataFormatLdapProperty(e, property) {
    var mod = this.state.mod;
    mod.parameters["data-format"][property].property = e.target.value;
    this.setState({mod: mod});
  }
  
  toggleDataFormatValue(e, property, value) {
    var mod = this.state.mod;
    mod.parameters["data-format"][property][value] = !mod.parameters["data-format"][property][value];
    this.setState({mod: mod});
  }
  
  toggleDataFormatMultiple(e, property) {
    var mod = this.state.mod;
    mod.parameters["data-format"][property]["multiple"] = !mod.parameters["data-format"][property]["multiple"];
    this.setState({mod: mod});
  }
  
  deleteDataFormat(e, property) {
    var mod = this.state.mod;
    delete(mod.parameters["data-format"][property]);
    this.setState({mod: mod});
  }
  
  changeParam(e, parameter, toArray = false) {
    var mod = this.state.mod;
    if (toArray) {
      mod.parameters[parameter] = e.target.value.replace(/ /g, '').split(',');
    } else {
      mod.parameters[parameter] = e.target.value;
    }
    this.setState({mod: mod});
  }
  
  addScopeMatch() {
    var mod = this.state.mod;
    if (!mod.parameters["scope-match"]) {
      mod.parameters["scope-match"] = [];
    }
    mod.parameters["scope-match"].push({"ldap-value": "", "scope-value": "", "match": "equals"});
    this.setState({mod: mod});
  }
  
  changeScopeMatchProperty(e, index, property) {
    var mod = this.state.mod;
    mod.parameters["scope-match"][index][property] = e.target.value;
    this.setState({mod: mod});
  }
  
  changeMatchType(e, index, type) {
    var mod = this.state.mod;
    mod.parameters["scope-match"][index].match = type;
    this.setState({mod: mod});
  }
  
  changePasswordAlgorithm(e, alg) {
    var mod = this.state.mod;
    mod.parameters["password-algorithm"] = alg;
    this.setState({mod: mod});
  }
  
  getMatchType(type) {
    if (type === "contains") {
      return i18next.t("admin.mod-ldap-scope-match-contains");
    } else if (type === "startswith") {
      return i18next.t("admin.mod-ldap-scope-match-startswith");
    } else if (type === "endswith") {
      return i18next.t("admin.mod-ldap-scope-match-endswith");
    } else {
      return i18next.t("admin.mod-ldap-scope-match-equals");
    }
  }
  
  changePageSize(e) {
    var mod = this.state.mod;
    mod.parameters["page-size"] = parseInt(e.target.value);
    this.setState({mod: mod});
  }
  
  deleteScopeMatch(index) {
    var mod = this.state.mod;
    mod.parameters["scope-match"].splice(index, 1);
    this.setState({mod: mod});
  }
  
  changeSearchScope(e, searchScope) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["search-scope"] = searchScope;
    this.setState({mod: mod});
  }
  
  changeConfidential(e, confidentialValue) {
    e.preventDefault();
    var mod = this.state.mod;
    mod.parameters["confidential"] = confidentialValue;
    this.setState({mod: mod});
  }
  
  checkParameters() {
    var errorList = {}, hasError = false;
    if (!this.state.mod.parameters["uri"]) {
      hasError = true;
      errorList["uri"] = i18next.t("admin.mod-ldap-uri-error")
    }
    if (!this.state.mod.parameters["bind-dn"]) {
      hasError = true;
      errorList["bind-dn"] = i18next.t("admin.mod-ldap-bind-dn-error")
    }
    if (!this.state.mod.parameters["bind-password"]) {
      hasError = true;
      errorList["bind-password"] = i18next.t("admin.mod-ldap-bind-password-error")
    }
    if (!this.state.mod.parameters["base-search"]) {
      hasError = true;
      errorList["base-search"] = i18next.t("admin.mod-ldap-base-search-error")
    }
    if (!this.state.mod.parameters["filter"]) {
      hasError = true;
      errorList["filter"] = i18next.t("admin.mod-ldap-filter-error")
    }
    if (!this.state.mod.parameters["scope-property"]) {
      hasError = true;
      errorList["scope-property"] = i18next.t("admin.mod-ldap-scope-property-error")
    }
    if (this.state.role === "user") {
      if (!this.state.mod.parameters["username-property"]) {
        hasError = true;
        errorList["username-property"] = i18next.t("admin.mod-ldap-username-property-error")
      }
    } else {
      if (!this.state.mod.parameters["client_id-property"]) {
        hasError = true;
        errorList["client_id-property"] = i18next.t("admin.mod-ldap-client_id-property-error")
      }
    }
    if (!this.state.mod.readonly) {
      if (!this.state.mod.parameters["rdn-property"]) {
        hasError = true;
        errorList["rdn-property"] = i18next.t("admin.mod-ldap-rdn-property-error")
      }
      if (!this.state.mod.readonly) {
        if (!this.state.mod.parameters["password-property"]) {
          hasError = true;
          errorList["password-property"] = i18next.t("admin.mod-ldap-password-property-error")
        }
        if ((this.state.mod.parameters["confidential"] === "1" || this.state.role === "user") && !this.state.mod.parameters["password-algorithm"]) {
          hasError = true;
          errorList["password-algorithm"] = i18next.t("admin.mod-ldap-password-algorithm-error")
        }
      }
      if (!this.state.mod.parameters["object-class"]) {
        hasError = true;
        errorList["object-class"] = i18next.t("admin.mod-ldap-object-class-error")
      }
    }
    if (!hasError) {
      this.setState({errorList: {}}, () => {
        if (this.state.role === "user") {
          messageDispatcher.sendMessage('ModEdit', {type: "modValid"});
        } else if (this.state.role === "client") {
          messageDispatcher.sendMessage('ModEdit', {type: "modValid"});
        }
      });
    } else {
      this.setState({errorList: errorList});
    }
  }
  
  render() {
    var dataFormat = [], scopeMatch = [];
    var i = 0;
    for (var property in this.state.mod.parameters["data-format"]) {
      console.log(property);
      var rwAccess = "";
      if (this.state.role === "user") {
        rwAccess = 
        <div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor={"mod-database-data-format-read-"+property}>{i18next.t("admin.mod-database-data-format-read")}</label>
              </div>
              <div className="input-group-text">
                <input type="checkbox" className="form-control" id={"mod-database-data-format-read-"+property} onChange={(e) => this.toggleDataFormatValue(e, property, "read")} checked={this.state.mod.parameters["data-format"][property]["read"]} />
              </div>
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor={"mod-database-data-format-write-"+property}>{i18next.t("admin.mod-database-data-format-write")}</label>
              </div>
              <div className="input-group-text">
                <input type="checkbox" className="form-control" id={"mod-database-data-format-write-"+property} onChange={(e) => this.toggleDataFormatValue(e, property, "write")} checked={this.state.mod.parameters["data-format"][property]["write"]} />
              </div>
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor={"mod-database-data-format-profile-read-"+property}>{i18next.t("admin.mod-database-data-format-profile-read")}</label>
              </div>
              <div className="input-group-text">
                <input type="checkbox" className="form-control" id={"mod-database-data-format-profile-read-"+property} onChange={(e) => this.toggleDataFormatValue(e, property, "profile-read")} checked={this.state.mod.parameters["data-format"][property]["profile-read"]} />
              </div>
            </div>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor={"mod-database-data-format-profile-write-"+property}>{i18next.t("admin.mod-database-data-format-profile-write")}</label>
              </div>
              <div className="input-group-text">
                <input type="checkbox" className="form-control" id={"mod-database-data-format-profile-write-"+property} onChange={(e) => this.toggleDataFormatValue(e, property, "profile-write")} checked={this.state.mod.parameters["data-format"][property]["profile-write"]} />
              </div>
            </div>
          </div>
        </div>
      }
      dataFormat.push(<div key={i++}>
        <hr/>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-database-data-format-name-"+property}>{i18next.t("admin.mod-database-data-format-property")}</label>
            </div>
            <input type="text" className="form-control" id={"mod-database-data-format-name-"+property} onChange={(e) => this.changeDataFormatProperty(e, property)} value={property} placeholder={i18next.t("admin.mod-database-data-format-property-ph")} />
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-database-data-format-ldap-name-"+property}>{i18next.t("admin.mod-database-data-format-ldap-property")}</label>
            </div>
            <input type="text" className="form-control" id={"mod-database-data-format-ldap-name-"+property} onChange={(e) => this.changeDataFormatLdapProperty(e, property)} value={this.state.mod.parameters["data-format"][property].property} placeholder={i18next.t("admin.mod-database-data-format-ldap-property-ph")} />
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-database-data-format-multiple-"+property}>{i18next.t("admin.mod-database-data-format-multiple")}</label>
            </div>
            <div className="input-group-text">
              <input type="checkbox" className="form-control" id={"mod-database-data-format-multiple-"+property} onChange={(e) => this.toggleDataFormatMultiple(e, property)} checked={this.state.mod.parameters["data-format"][property]["multiple"]} />
            </div>
          </div>
        </div>
        {rwAccess}
        <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteDataFormat(e, property)} title={i18next.t("admin.mod-data-format-delete")}>
          <i className="fas fa-trash"></i>
        </button>
      </div>);
    }
    this.state.mod.parameters["scope-match"].forEach((match, index) => {
      scopeMatch.push(<div key={index}>
        <hr/>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-ldap-scope-match-ldap-"+index}>{i18next.t("admin.mod-ldap-scope-match-ldap")}</label>
            </div>
            <input type="text" className="form-control" id={"mod-ldap-scope-match-ldap-"+index} onChange={(e) => this.changeScopeMatchProperty(e, index, "ldap-value")} value={match["ldap-value"]} placeholder={i18next.t("admin.mod-ldap-scope-match-ldap-ph")} />
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"mod-ldap-scope-match-scope-"+index}>{i18next.t("admin.mod-ldap-scope-match-scope")}</label>
            </div>
            <input type="text" className="form-control" id={"mod-ldap-scope-match-scope-"+index} onChange={(e) => this.changeScopeMatchProperty(e, index, "scope-value")} value={match["scope-value"]} placeholder={i18next.t("admin.mod-ldap-scope-match-scope-ph")} />
          </div>
        </div>
        <div className="form-group">
          <div className="btn-group" role="group">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor={"dropdownMatchType-"+index}>{i18next.t("admin.mod-ldap-scope-match")}</label>
            </div>
            <div className="dropdown">
              <button className="btn btn-secondary dropdown-toggle" type="button" id={"dropdownMatchType-"+index} data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {this.getMatchType(match["match"])}
              </button>
              <div className="dropdown-menu" aria-labelledby={"dropdownMatchType-"+index}>
                <a className="dropdown-item" href="#" onClick={(e) => this.changeMatchType(e, index, 'equals')}>{i18next.t("admin.mod-ldap-scope-match-equals")}</a>
                <a className="dropdown-item" href="#" onClick={(e) => this.changeMatchType(e, index, 'contains')}>{i18next.t("admin.mod-ldap-scope-match-contains")}</a>
                <a className="dropdown-item" href="#" onClick={(e) => this.changeMatchType(e, index, 'startswith')}>{i18next.t("admin.mod-ldap-scope-match-startswith")}</a>
                <a className="dropdown-item" href="#" onClick={(e) => this.changeMatchType(e, index, 'endswith')}>{i18next.t("admin.mod-ldap-scope-match-endswith")}</a>
              </div>
            </div>
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <button type="button" className="btn btn-secondary" onClick={() => this.deleteScopeMatch(index)} title={i18next.t("admin.mod-ldap-scope-match-delete")}>
              <i className="fas fa-trash"></i>
            </button>
          </div>
        </div>
      </div>
      );
    });
    var usernameJsx = "", emailJsx = "", descriptionJsx = "", client_idJsx = "", confidentialJsx = "";
    if (this.state.role === "user") {
      usernameJsx = 
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-username-property">{i18next.t("admin.mod-ldap-username-property")}</label>
            </div>
            <input type="text" className={this.state.errorList["username-property"]?"form-control is-invalid":"form-control"} id="mod-ldap-username-property" onChange={(e) => this.changeParam(e, "username-property", true)} value={this.state.mod.parameters["username-property"]} placeholder={i18next.t("admin.mod-ldap-username-property-ph")} />
          </div>
          {this.state.errorList["username-property"]?<span className="error-input">{i18next.t(this.state.errorList["username-property"])}</span>:""}
        </div>;
      emailJsx =
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-email-property">{i18next.t("admin.mod-ldap-email-property")}</label>
            </div>
            <input type="text" className="form-control" id="mod-ldap-email-property" onChange={(e) => this.changeParam(e, "email-property", true)} value={this.state.mod.parameters["email-property"]} placeholder={i18next.t("admin.mod-ldap-email-property-ph")} />
          </div>
        </div>;
    } else {
      client_idJsx =
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-client_id-property">{i18next.t("admin.mod-ldap-client_id-property")}</label>
            </div>
            <input type="text" className={this.state.errorList["client_id-property"]?"form-control is-invalid":"form-control"} id="mod-ldap-username-property" onChange={(e) => this.changeParam(e, "client_id-property", true)} value={this.state.mod.parameters["client_id-property"]} placeholder={i18next.t("admin.mod-ldap-client_id-property-ph")} />
          </div>
          {this.state.errorList["client_id-property"]?<span className="error-input">{i18next.t(this.state.errorList["client_id-property"])}</span>:""}
        </div>;
      descriptionJsx = 
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-description-property">{i18next.t("admin.mod-ldap-description-property")}</label>
            </div>
            <input type="text" className="form-control" id="mod-ldap-description-property" onChange={(e) => this.changeParam(e, "description-property", true)} value={this.state.mod.parameters["description-property"]} placeholder={i18next.t("admin.mod-ldap-description-property-ph")} />
          </div>
        </div>;
      confidentialJsx = 
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-confidential">{i18next.t("admin.mod-ldap-confidential")}</label>
            </div>
            <div className="dropdown">
              <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-ldap-confidential" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {(this.state.mod.parameters["confidential"]==="1"?i18next.t("admin.mod-ldap-confidential-1"):i18next.t("admin.mod-ldap-confidential-0"))}
              </button>
              <div className="dropdown-menu" aria-labelledby="mod-ldap-search-scope">
                <a className={"dropdown-item"+(this.state.mod.parameters["confidential"]!=="1"?" active":"")} href="#" onClick={(e) => this.changeConfidential(e, '0')}>{i18next.t("admin.mod-ldap-confidential-0")}</a>
                <a className={"dropdown-item"+(this.state.mod.parameters["confidential"]==="1"?" active":"")} href="#" onClick={(e) => this.changeConfidential(e, '1')}>{i18next.t("admin.mod-ldap-confidential-1")}</a>
              </div>
            </div>
          </div>
        </div>;
    }
    return (
      <div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-uri">{i18next.t("admin.mod-ldap-uri")}</label>
            </div>
            <input type="text" className={this.state.errorList["uri"]?"form-control is-invalid":"form-control"} id="mod-ldap-uri" onChange={(e) => this.changeParam(e, "uri")} value={this.state.mod.parameters["uri"]} placeholder={i18next.t("admin.mod-ldap-uri-ph")} />
          </div>
          {this.state.errorList["uri"]?<span className="error-input">{i18next.t(this.state.errorList["uri"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-bind-dn">{i18next.t("admin.mod-ldap-bind-dn")}</label>
            </div>
            <input type="text" className={this.state.errorList["bind-dn"]?"form-control is-invalid":"form-control"} id="mod-ldap-bind-dn" onChange={(e) => this.changeParam(e, "bind-dn")} value={this.state.mod.parameters["bind-dn"]} placeholder={i18next.t("admin.mod-ldap-bind-dn-ph")} />
          </div>
          {this.state.errorList["bind-dn"]?<span className="error-input">{i18next.t(this.state.errorList["bind-dn"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-bind-password">{i18next.t("admin.mod-ldap-bind-password")}</label>
            </div>
            <input type="password" className={this.state.errorList["bind-password"]?"form-control is-invalid":"form-control"} id="mod-ldap-bind-password" onChange={(e) => this.changeParam(e, "bind-password")} value={this.state.mod.parameters["bind-password"]} placeholder={i18next.t("admin.mod-ldap-bind-password-ph")} />
          </div>
          {this.state.errorList["bind-password"]?<span className="error-input">{i18next.t(this.state.errorList["bind-password"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-page-size">{i18next.t("admin.mod-ldap-page-size")}</label>
            </div>
            <input type="number" min="0" step="1" className="form-control" id="mod-ldap-page-size" onChange={this.changePageSize} value={this.state.mod.parameters["page-size"]} placeholder={i18next.t("admin.mod-ldap-page-size-ph")} />
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-base-search">{i18next.t("admin.mod-ldap-base-search")}</label>
            </div>
            <input type="text" className={this.state.errorList["base-search"]?"form-control is-invalid":"form-control"} id="mod-ldap-base-search" onChange={(e) => this.changeParam(e, "base-search")} value={this.state.mod.parameters["base-search"]} placeholder={i18next.t("admin.mod-ldap-base-search-ph")} />
          </div>
          {this.state.errorList["base-search"]?<span className="error-input">{i18next.t(this.state.errorList["base-search"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-base-search">{i18next.t("admin.mod-ldap-search-scope")}</label>
            </div>
            <div className="dropdown">
              <button className="btn btn-secondary dropdown-toggle" type="button" id="mod-ldap-search-scope" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {i18next.t("admin.mod-ldap-search-scope-" + this.state.mod.parameters["search-scope"])}
              </button>
              <div className="dropdown-menu" aria-labelledby="mod-ldap-search-scope">
                <a className={"dropdown-item"+(this.state.mod.parameters["search-scope"]==="one"?" active":"")} href="#" onClick={(e) => this.changeSearchScope(e, 'one')}>{i18next.t("admin.mod-ldap-search-scope-one")}</a>
                <a className={"dropdown-item"+(this.state.mod.parameters["search-scope"]==="subtree"?" active":"")} href="#" onClick={(e) => this.changeSearchScope(e, 'subtree')}>{i18next.t("admin.mod-ldap-search-scope-subtree")}</a>
                <a className={"dropdown-item"+(this.state.mod.parameters["search-scope"]==="children"?" active":"")} href="#" onClick={(e) => this.changeSearchScope(e, 'children')}>{i18next.t("admin.mod-ldap-search-scope-children")}</a>
              </div>
            </div>
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-filter">{i18next.t("admin.mod-ldap-filter")}</label>
            </div>
            <input type="text" className={this.state.errorList["filter"]?"form-control is-invalid":"form-control"} id="mod-ldap-filter" onChange={(e) => this.changeParam(e, "filter")} value={this.state.mod.parameters["filter"]} placeholder={i18next.t("admin.mod-ldap-filter-ph")} />
          </div>
          {this.state.errorList["filter"]?<span className="error-input">{i18next.t(this.state.errorList["filter"])}</span>:""}
        </div>
        {usernameJsx}
        {client_idJsx}
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-name-property">{i18next.t("admin.mod-ldap-name-property")}</label>
            </div>
            <input type="text" className="form-control" id="mod-ldap-name-property" onChange={(e) => this.changeParam(e, "name-property", true)} value={this.state.mod.parameters["name-property"]} placeholder={i18next.t("admin.mod-ldap-name-property-ph")} />
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-scope-property">{i18next.t("admin.mod-ldap-scope-property")}</label>
            </div>
            <input type="text" className={this.state.errorList["scope-property"]?"form-control is-invalid":"form-control"} id="mod-ldap-scope-property" onChange={(e) => this.changeParam(e, "scope-property", true)} value={this.state.mod.parameters["scope-property"]} placeholder={i18next.t("admin.mod-ldap-scope-property-ph")} />
          </div>
          {this.state.errorList["scope-property"]?<span className="error-input">{i18next.t(this.state.errorList["scope-property"])}</span>:""}
        </div>
        {emailJsx}
        {descriptionJsx}
        {confidentialJsx}
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-password-property">{i18next.t("admin.mod-ldap-password-property")}</label>
            </div>
            <input disabled={this.state.mod.readonly || (this.state.mod.parameters["confidential"] !== "1" && this.state.role === "client")} type="text" className={this.state.errorList["password-property"]?"form-control is-invalid":"form-control"} id="mod-ldap-password-property" onChange={(e) => this.changeParam(e, "password-property")} value={this.state.mod.parameters["password-property"]} placeholder={i18next.t("admin.mod-ldap-password-property-ph")} />
          </div>
          {this.state.errorList["password-property"]?<span className="error-input">{i18next.t(this.state.errorList["password-property"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="dropdownPasswordAlgorithm">{i18next.t("admin.mod-ldap-password-algorithm")}</label>
            </div>
            <div className="dropdown">
              <button disabled={this.state.mod.readonly} className={this.state.errorList["password-algorithm"]?"btn btn-secondary dropdown-toggle is-invalid":"btn btn-secondary dropdown-toggle"} type="button" id={"dropdownPasswordAlgorithm"} data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                {this.state.mod.parameters["password-algorithm"] || i18next.t("admin.mod-ldap-password-algorithm-select")}
              </button>
              <div className="dropdown-menu" aria-labelledby={"dropdownPasswordAlgorithm"}>
                <a className="dropdown-item" href="#" onClick={(e) => this.changePasswordAlgorithm(e, 'SSHA')}>{i18next.t("admin.mod-ldap-password-algorithm-ssha")}</a>
                <a className="dropdown-item" href="#" onClick={(e) => this.changePasswordAlgorithm(e, 'SHA')}>{i18next.t("admin.mod-ldap-password-algorithm-sha")}</a>
                <a className="dropdown-item" href="#" onClick={(e) => this.changePasswordAlgorithm(e, 'SMD5')}>{i18next.t("admin.mod-ldap-password-algorithm-smd5")}</a>
                <a className="dropdown-item" href="#" onClick={(e) => this.changePasswordAlgorithm(e, 'MD5')}>{i18next.t("admin.mod-ldap-password-algorithm-md5")}</a>
                <a className="dropdown-item" href="#" onClick={(e) => this.changePasswordAlgorithm(e, 'PLAIN')}>{i18next.t("admin.mod-ldap-password-algorithm-plain")}</a>
              </div>
            </div>
            {this.state.errorList["password-algorithm"]?<span className="error-input">{i18next.t(this.state.errorList["password-algorithm"])}</span>:""}
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-rdn-property">{i18next.t("admin.mod-ldap-rdn-property")}</label>
            </div>
            <input disabled={this.state.mod.readonly} type="text" className={this.state.errorList["rdn-property"]?"form-control is-invalid":"form-control"} id="mod-ldap-rdn-property" onChange={(e) => this.changeParam(e, "rdn-property")} value={this.state.mod.parameters["rdn-property"]} placeholder={i18next.t("admin.mod-ldap-rdn-property-ph")} />
          </div>
          {this.state.errorList["rdn-property"]?<span className="error-input">{i18next.t(this.state.errorList["rdn-property"])}</span>:""}
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-ldap-object-class">{i18next.t("admin.mod-ldap-object-class")}</label>
            </div>
            <input disabled={this.state.mod.readonly} type="text" className={this.state.errorList["object-class"]?"form-control is-invalid":"form-control"} id="mod-ldap-object-class" onChange={(e) => this.changeParam(e, "object-class", true)} value={this.state.mod.parameters["object-class"]} placeholder={i18next.t("admin.mod-ldap-object-class-ph")} />
          </div>
          {this.state.errorList["object-class"]?<span className="error-input">{i18next.t(this.state.errorList["object-class"])}</span>:""}
        </div>
        <div className="accordion" id="accordionParams">
          <div className="card">
            <div className="card-header" id="dataFormatCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseDataFormat" aria-expanded="true" aria-controls="collapseDataFormat">
                  {i18next.t("admin.mod-data-format")}
                </button>
              </h2>
            </div>
            <div id="collapseDataFormat" className="collapse" aria-labelledby="dataFormatCard" data-parent="#accordionParams">
              <div className="card-body">
                <p>{i18next.t("admin.mod-data-format-message")}</p>
                <button type="button" className="btn btn-secondary" onClick={this.addDataFormat} title={i18next.t("admin.mod-data-format-add")}>
                  <i className="fas fa-plus"></i>
                </button>
                {dataFormat}
              </div>
            </div>
          </div>
          <div className="card">
            <div className="card-header" id="scopeMatchCard">
              <h2 className="mb-0">
                <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseScopeMatch" aria-expanded="true" aria-controls="collapseScopeMatch">
                  {i18next.t("admin.mod-scope-match")}
                </button>
              </h2>
            </div>
            <div id="collapseScopeMatch" className="collapse" aria-labelledby="scopeMatchCard" data-parent="#accordionParams">
              <div className="card-body">
                <button type="button" className="btn btn-secondary" onClick={this.addScopeMatch} title={i18next.t("admin.mod-scope-match-add")}>
                  <i className="fas fa-plus"></i>
                </button>
                {scopeMatch}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default LDAPParams;
