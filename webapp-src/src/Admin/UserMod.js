import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';
import apiManager from '../lib/APIManager';

class UserMod extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      mods: props.mods,
      curMod: {},
      types: props.types
    }
    
    this.addMod = this.addMod.bind(this);
    this.editMod = this.editMod.bind(this);
    this.deleteMod = this.deleteMod.bind(this);
    this.switchModStatus = this.switchModStatus.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      mods: nextProps.mods,
      types: nextProps.types
    });
  }

  addMod(e) {
    messageDispatcher.sendMessage('App', {type: "add", role: "userMod"});
  }

  editMod(e, mod) {
    messageDispatcher.sendMessage('App', {type: "edit", role: "userMod", mod: mod});
  }

  deleteMod(e, mod) {
    messageDispatcher.sendMessage('App', {type: "delete", role: "userMod", mod: mod});
  }

  moveModUp(e, mod, previousMod) {
    mod.order_rank--;
    previousMod.order_rank++;
    messageDispatcher.sendMessage('App', {type: "swap", role: "userMod", mod: mod, previousMod: previousMod});
  }

  switchModStatus(mod) {
    var action = (mod.enabled?"disable":"enable");
    apiManager.glewlwydRequest("/mod/user/" + encodeURI(mod.name) + "/" + action + "/", "PUT")
    .then(() => {
      messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("admin.success-api-edit-mod")});
    })
    .fail((err) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("admin.error-api-edit-mod")});
      if (err.status === 400) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: JSON.stringify(err.responseJSON)});
      }
    })
    .always(() => {
      messageDispatcher.sendMessage('App', {type: "refresh", role: "userMod", mod: mod});
    });
  }

	render() {
    var mods = [];
    this.state.mods.forEach((mod, index) => {
      var module = "", buttonUp = "", switchButton = "";
      this.state.types.forEach((type) => {
        if (mod.module === type.name) {
          module = type.display_name;
        }
      });
      if (index) {
        buttonUp = 
          <button type="button" className="btn btn-secondary" onClick={(e) => this.moveModUp(e, mod, this.state.mods[index - 1])} title={i18next.t("admin.move-up")}>
            <i className="fas fa-sort-up"></i>
          </button>
      }
      if (mod.enabled) {
        switchButton = <button type="button" className="btn btn-secondary" onClick={(e) => this.switchModStatus(mod)} title={i18next.t("admin.switch-off")}>
          <i className="fas fa-toggle-on"></i>
        </button>;
      } else {
        switchButton = <button type="button" className="btn btn-secondary" onClick={(e) => this.switchModStatus(mod)} title={i18next.t("admin.switch-om")}>
          <i className="fas fa-toggle-off"></i>
        </button>;
      }
      mods.push(<tr key={index}>
        <td>{mod.order_rank}</td>
        <td>{module}</td>
        <td>{mod.name}</td>
        <td>{mod.display_name||""}</td>
        <td>{(mod.readonly?i18next.t("admin.yes"):i18next.t("admin.no"))}</td>
        <td>{(mod.enabled?i18next.t("admin.yes"):i18next.t("admin.no"))}</td>
        <td>
          <div className="btn-group" role="group">
            {switchButton}
            <button type="button" className="btn btn-secondary" onClick={(e) => this.editMod(e, mod)} title={i18next.t("admin.edit")}>
              <i className="fas fa-edit"></i>
            </button>
            <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteMod(e, mod)} title={i18next.t("admin.delete")}>
              <i className="fas fa-trash"></i>
            </button>
            {buttonUp}
          </div>
        </td>
      </tr>);
    });
		return (
    <table className="table table-responsive table-striped">
      <thead>
        <tr>
          <th colSpan="5">
            <h4>{i18next.t("admin.user-mod-list-title")}</h4>
          </th>
          <th colSpan="1">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.addMod(e)} title={i18next.t("admin.add")}>
              <i className="fas fa-plus"></i>
            </button>
          </th>
        </tr>
        <tr>
          <th>
            {i18next.t("admin.order")}
          </th>
          <th>
            {i18next.t("admin.type")}
          </th>
          <th>
            {i18next.t("admin.name")}
          </th>
          <th>
            {i18next.t("admin.display-name")}
          </th>
          <th>
            {i18next.t("admin.readonly")}
          </th>
          <th>
            {i18next.t("admin.enabled")}
          </th>
          <th>
          </th>
        </tr>
      </thead>
      <tbody>
        {mods}
      </tbody>
    </table>
		);
	}
}

export default UserMod;
