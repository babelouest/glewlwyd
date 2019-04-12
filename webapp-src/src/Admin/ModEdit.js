import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import ModEditParameters from './ModEditParameters';

class ModEdit extends Component {
  constructor(props) {
    super(props);

    this.state = {
      title: props.title,
      mod: props.mod,
      role: props.role,
      modTypes: props.types,
      add: props.add,
      callback: props.callback,
      parametersValid: true,
      nameInvalid: false,
      nameInvalidMessage: false,
      typeInvalidMessage: false
    }

    this.closeModal = this.closeModal.bind(this);
    this.changeName = this.changeName.bind(this);
    this.changeDisplayName = this.changeDisplayName.bind(this);
    this.changeType = this.changeType.bind(this);
    this.toggleReadonly = this.toggleReadonly.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
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
                this.state.callback(result, this.state.mod);
              }
            });
          } else {
            this.state.callback(result, this.state.mod);
          }
        }
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
  
  toggleReadonly(e) {
    var mod = this.state.mod;
    mod.readonly = !mod.readonly;
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
    if (this.state.role !== "scheme") {
      readonly = <div className="form-group">
        <label htmlFor="mod-readonly">{i18next.t("admin.mod-readonly")}</label>
        <input type="checkbox" className="form-control" id="mod-readonly" onChange={(e) => this.toggleReadonly(e)} checked={this.state.mod.readonly||false} />
      </div>;
    }
		return (
    <div className="modal fade" id="editModModal" tabIndex="-1" role="dialog" aria-labelledby="confirmModalLabel" aria-hidden="true">
      <div className="modal-dialog" role="document">
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
                <label htmlFor="mod-name">{i18next.t("admin.mod-name")}</label>
                <input type="text" className={"form-control" + (this.state.nameInvalid?" is-invalid":"")} id="mod-name" placeholder={i18next.t("admin.mod-name-ph")} maxLength="128" value={this.state.mod.name||""} onChange={(e) => this.changeName(e)} disabled={!this.state.add} />
                <span className={"error-input" + (this.state.nameInvalid?"":" hidden")}>{this.state.nameInvalidMessage}</span>
              </div>
              <div className="form-group">
                <label htmlFor="mod-display-name">{i18next.t("admin.mod-display-name")}</label>
                <input type="text" className="form-control" id="mod-display-name" placeholder={i18next.t("admin.mod-display-name-ph")} maxLength="256" value={this.state.mod.display_name||""} onChange={(e) => this.changeDisplayName(e)}/>
              </div>
              <div className="form-group">
                <label htmlFor="mod-type">{i18next.t("admin.mod-type")}</label>
                {modType}
                <span className={"error-input" + (this.state.typeInvalidMessage?"":" hidden")}>{this.state.typeInvalidMessage}</span>
              </div>
              {readonly}
              <ModEditParameters mod={this.state.mod} role={this.state.role} />
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
