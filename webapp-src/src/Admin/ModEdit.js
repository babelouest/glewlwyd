import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import ModEditParameters from './ModEditParameters';
import messageDispatcher from '../lib/MessageDispatcher';

class ModEdit extends Component {
  constructor(props) {
    super(props);
    
    if (!props.mod) {
      props.mod = {};
    }
    
    if (!props.mod.expiration) {
      props.mod.expiration = 600;
    }
    
    if (!props.mod.max_use) {
      props.mod.max_use = 0;
    }

    if (props.mod.allow_user_register === undefined) {
      props.mod.allow_user_register = true;
    }
    
    if (props.role === "client") {
      if (props.mod.parameters["data-format"] === undefined) {
        props.mod.parameters["data-format"]  = {};
      }
      if (props.mod.parameters["data-format"]["redirect_uri"] === undefined) {
        props.mod.parameters["data-format"]["redirect_uri"] = {multiple: true, read: true, write: true};
      }
      if (props.mod.parameters["data-format"]["authorization_type"] === undefined) {
        props.mod.parameters["data-format"]["authorization_type"] = {multiple: true, read: true, write: true};
      }
      if (props.mod.parameters["data-format"]["sector_identifier_uri"] === undefined) {
        props.mod.parameters["data-format"]["sector_identifier_uri"] = {multiple: false, read: true, write: true};
      }
    }

    this.state = {
      config: props.config,
      title: props.title,
      mod: props.mod,
      role: props.role,
      modTypes: props.types,
      add: props.add,
      callback: props.callback,
      parametersValid: true,
      nameInvalid: false,
      nameInvalidMessage: false,
      typeInvalidMessage: false,
      check: false
    }
    
    messageDispatcher.subscribe('ModEdit', (message) => {
      if (message.type === 'modValid') {
        this.setState({check: false}, () => {
          if (this.state.add && !this.state.mod.name) {
            this.setState({nameInvalid: true, nameInvalidMessage: i18next.t("admin.error-mod-name-mandatory"), typeInvalidMessage: false});
          } else if (!this.state.mod.module) {
            this.setState({nameInvalid: false, nameInvalidMessage: false, typeInvalidMessage: i18next.t("admin.error-mod-type-mandatory")});
          } else if (this.state.parametersValid) {
            if (this.state.add) {
              apiManager.glewlwydRequest("/mod/" + this.state.role + "/" + encodeURI(this.state.mod.name), "GET")
              .then(() => {
                this.setState({nameInvalid: true, nameInvalidMessage: i18next.t("admin.error-mod-name-exist"), typeInvalidMessage: false});
              })
              .fail((err) => {
                if (err.status === 404) {
                  this.state.callback(true, this.state.mod);
                }
              });
            } else {
              this.state.callback(true, this.state.mod);
            }
          }
        });
      }
    });

    this.closeModal = this.closeModal.bind(this);
    this.changeName = this.changeName.bind(this);
    this.changeDisplayName = this.changeDisplayName.bind(this);
    this.changeType = this.changeType.bind(this);
    this.toggleReadonly = this.toggleReadonly.bind(this);
    this.toggleAllowUserRegister = this.toggleAllowUserRegister.bind(this);
  }

  UNSAFE_componentWillReceiveProps(nextProps) {
    
    if (!nextProps.mod) {
      nextProps.mod = {};
    }
    
    if (!nextProps.mod.expiration) {
      nextProps.mod.expiration = 600;
    }
    
    if (!nextProps.mod.max_use) {
      nextProps.mod.max_use = 0;
    }

    if (nextProps.mod.allow_user_register === undefined) {
      nextProps.mod.allow_user_register = true;
    }

    if (nextProps.role === "client") {
      if (nextProps.mod.parameters["data-format"] === undefined) {
        nextProps.mod.parameters["data-format"]  = {};
      }
      if (nextProps.mod.parameters["data-format"]["redirect_uri"] === undefined) {
        nextProps.mod.parameters["data-format"]["redirect_uri"] = {multiple: true, read: true, write: true};
      }
      if (nextProps.mod.parameters["data-format"]["authorization_type"] === undefined) {
        nextProps.mod.parameters["data-format"]["authorization_type"] = {multiple: true, read: true, write: true};
      }
      if (nextProps.mod.parameters["data-format"]["sector_identifier_uri"] === undefined) {
        nextProps.mod.parameters["data-format"]["sector_identifier_uri"] = {multiple: false, read: true, write: true};
      }
    }

    this.setState({
      config: nextProps.config,
      title: nextProps.title,
      mod: nextProps.mod,
      role: nextProps.role,
      modTypes: nextProps.types,
      add: nextProps.add,
      callback: nextProps.callback,
      parametersValid: true,
      nameInvalid: false,
      nameInvalidMessage: false,
      typeInvalidMessage: false
    });
  }
    
  closeModal(e, result) {
    if (this.state.callback) {
      if (result) {
        this.setState({check: true});
      } else {
        this.state.callback(result);
      }
    }
  }
  
  changeName(e) {
    var mod = this.state.mod;
    mod.name = e.target.value;
    this.setState({mod: mod});
  }
  
  changeDisplayName(e) {
    var mod = this.state.mod;
    mod.display_name = e.target.value;
    this.setState({mod: mod});
  }
  
  changeType(e, name) {
    var mod = this.state.mod;
    mod.module = name;
    this.setState({mod: mod});
  }
  
  changeExpiration(e) {
    var mod = this.state.mod;
    mod.expiration = parseInt(e.target.value);
    this.setState({mod: mod});
  }
  
  changeMaxUse(e) {
    var mod = this.state.mod;
    mod.max_use = parseInt(e.target.value);
    this.setState({mod: mod});
  }
  
  toggleReadonly(e) {
    var mod = this.state.mod;
    mod.readonly = !mod.readonly;
    this.setState({mod: mod});
  }
  
  toggleAllowUserRegister() {
    var mod = this.state.mod;
    mod.allow_user_register = !mod.allow_user_register;
    this.setState({mod: mod});
  }
  
	render() {
    var typeList = [];
    var modType;
    if (this.state.add) {
      var dropdownTitle = i18next.t("admin.mod-type-select");
      this.state.modTypes.forEach((mod, index) => {
        if (this.state.mod.module === mod.name) {
          dropdownTitle = mod.display_name;
          typeList.push(<a className="dropdown-item active" key={index} href="#" onClick={(e) => this.changeType(e, mod.name)}>{mod.display_name}</a>);
        } else {
          typeList.push(<a className="dropdown-item" key={index} href="#" onClick={(e) => this.changeType(e, mod.name)}>{mod.display_name}</a>);
        }
      });
      modType = <div className="dropdown">
        <button className="btn btn-secondary dropdown-toggle" type="button" id="dropdownModType" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
          {dropdownTitle}
        </button>
        <div className="dropdown-menu" aria-labelledby="dropdownModType">
          {typeList}
        </div>
      </div>
    } else {
      this.state.modTypes.forEach((mod, index) => {
        if (this.state.mod.module === mod.name) {
          modType = <span className="badge badge-primary btn-icon-right">{mod.display_name}</span>
        }
      });
    }
    var readonly = "";
    var schemeParams = "";
    if (this.state.role !== "scheme") {
      readonly = 
      <div className="form-group">
        <div className="input-group mb-3">
          <div className="input-group-prepend">
            <label className="input-group-text" htmlFor="mod-readonly">{i18next.t("admin.mod-readonly")}</label>
          </div>
          <div className="input-group-text">
            <input type="checkbox" className="form-control" id="mod-readonly" onChange={(e) => this.toggleReadonly(e)} checked={this.state.mod.readonly||this.state.mod.module==="http"||false} />
          </div>
        </div>
      </div>;
    } else {
      schemeParams = <div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-expiration">{i18next.t("admin.mod-expiration")}</label>
            </div>
            <input type="number" min="0" step="1" className="form-control" id="mod-expiration" placeholder={i18next.t("admin.mod-expiration-ph")} value={this.state.mod.expiration} onChange={(e) => this.changeExpiration(e)}/>
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-max-use">{i18next.t("admin.mod-max-use")}</label>
            </div>
            <input type="number" min="0" step="1" className="form-control" id="mod-max-use" placeholder={i18next.t("admin.mod-max-use-ph")} value={this.state.mod.max_use} onChange={(e) => this.changeMaxUse(e)}/>
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="mod-allow-user-register">{i18next.t("admin.mod-allow-user-register")}</label>
            </div>
            <div className="input-group-text">
              <input type="checkbox" className="form-control" id="mod-allow-user-register" onChange={(e) => this.toggleAllowUserRegister(e)} checked={this.state.mod.allow_user_register} />
            </div>
          </div>
        </div>
      </div>
    }
		return (
    <div className="modal fade" id="editModModal" tabIndex="-1" role="dialog" aria-labelledby="confirmModalLabel" aria-hidden="true">
      <div className="modal-dialog modal-lg" role="document">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title" id="confirmModalLabel">{this.state.title}</h5>
            <button type="button" className="close" aria-label={i18next.t("modal.close")} onClick={(e) => this.closeModal(e, false)}>
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div className="modal-body">
            <form className="needs-validation" noValidate>
              <div className="form-group">
                <div className="input-group mb-3">
                  <div className="input-group-prepend">
                    <label className="input-group-text" htmlFor="mod-type">{i18next.t("admin.mod-type")}</label>
                  </div>
                  {modType}
                  <span className={"error-input" + (this.state.typeInvalidMessage?"":" hidden")}>{this.state.typeInvalidMessage}</span>
                </div>
              </div>
              <div className="form-group">
                <div className="input-group mb-3">
                  <div className="input-group-prepend">
                    <label className="input-group-text" htmlFor="mod-name">{i18next.t("admin.mod-name")}</label>
                  </div>
                  <input type="text" className={"form-control" + (this.state.nameInvalid?" is-invalid":"")} id="mod-name" placeholder={i18next.t("admin.mod-name-ph")} maxLength="128" value={this.state.mod.name||""} onChange={(e) => this.changeName(e)} disabled={!this.state.add} />
                  <span className={"error-input" + (this.state.nameInvalid?"":" hidden")}>{this.state.nameInvalidMessage}</span>
                </div>
              </div>
              <div className="form-group">
                <div className="input-group mb-3">
                  <div className="input-group-prepend">
                    <label className="input-group-text" htmlFor="mod-display-name">{i18next.t("admin.mod-display-name")}</label>
                  </div>
                  <input type="text" className="form-control" id="mod-display-name" placeholder={i18next.t("admin.mod-display-name-ph")} maxLength="256" value={this.state.mod.display_name||""} onChange={(e) => this.changeDisplayName(e)}/>
                </div>
              </div>
              {readonly}
              {schemeParams}
              <ModEditParameters mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
            </form>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.closeModal(e, false)}>{i18next.t("modal.close")}</button>
            <button type="button" className="btn btn-primary" onClick={(e) => this.closeModal(e, true)}>{i18next.t("modal.ok")}</button>
          </div>
        </div>
      </div>
    </div>
		);
	}
}

export default ModEdit;
