import React, { Component } from 'react';
import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';
import apiManager from '../lib/APIManager';

class UserMod extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      mods: props.mods,
      curMod: {},
      types: props.types,
      loggedIn: props.loggedIn
    }
    
    this.addMod = this.addMod.bind(this);
    this.editMod = this.editMod.bind(this);
    this.deleteMod = this.deleteMod.bind(this);
    this.switchModStatus = this.switchModStatus.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      mods: nextProps.mods,
      types: nextProps.types,
      loggedIn: nextProps.loggedIn
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
    apiManager.glewlwydRequest("/mod/user/" + encodeURIComponent(mod.name) + "/" + action + "/", "PUT")
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
      var module = "", buttonUp = "", switchButton = "", buttonUpSmall, switchButtonSmall;
      this.state.types.forEach((type) => {
        if (mod.module === type.name) {
          module = type.display_name;
        }
      });
      if (index) {
        buttonUp = 
          <button type="button" className="btn btn-secondary" onClick={(e) => this.moveModUp(e, mod, this.state.mods[index - 1])} title={i18next.t("admin.move-up")}>
            <i className="fas fa-sort-up"></i>
          </button>;
        buttonUpSmall = <a className="dropdown-item" href="#" onClick={(e) => moveModUp(e, mod, this.state.mods[index - 1])} alt={i18next.t("admin.move-up")}>
          <i className="fas fa-sort-up btn-icon"></i>
          {i18next.t("admin.move-up")}
        </a>
      }
      if (mod.enabled) {
        switchButton = <button type="button" className="btn btn-secondary" onClick={(e) => this.switchModStatus(mod)} title={i18next.t("admin.switch-off")}>
          <i className="fas fa-toggle-off"></i>
        </button>;
        switchButtonSmall = <a className="dropdown-item" href="#" onClick={(e) => this.switchModStatus(mod)} alt={i18next.t("admin.switch-off")}>
          <i className="fas fa-toggle-on btn-icon"></i>
          {i18next.t("admin.switch-off")}
        </a>
      } else {
        switchButton = <button type="button" className="btn btn-secondary" onClick={(e) => this.switchModStatus(mod)} title={i18next.t("admin.switch-on")}>
          <i className="fas fa-toggle-on"></i>
        </button>;
        switchButtonSmall = <a className="dropdown-item" href="#" onClick={(e) => this.switchModStatus(mod)} alt={i18next.t("admin.switch-on")}>
          <i className="fas fa-toggle-on btn-icon"></i>
          {i18next.t("admin.switch-on")}
        </a>
      }
      mods.push(<tr key={index}>
        <td className="d-none d-lg-table-cell">{mod.order_rank}</td>
        <td>{module}</td>
        <td>{mod.name}</td>
        <td className="d-none d-lg-table-cell">{mod.display_name||""}</td>
        <td className="d-none d-lg-table-cell">{(mod.readonly?i18next.t("admin.yes"):i18next.t("admin.no"))}</td>
        <td className="d-none d-lg-table-cell">{(mod.enabled?i18next.t("admin.yes"):i18next.t("admin.no"))}</td>
        <td>
          <div className="btn-group d-none d-lg-table-cell" role="group">
            {switchButton}
            <button type="button" className="btn btn-secondary" onClick={(e) => this.editMod(e, mod)} title={i18next.t("admin.edit")}>
              <i className="fas fa-edit"></i>
            </button>
            <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteMod(e, mod)} title={i18next.t("admin.delete")}>
              <i className="fas fa-trash"></i>
            </button>
            {buttonUp}
          </div>
          <div className="dropdown d-block d-lg-none">
            <button className="btn btn-secondary dropdown-toggle" type="button" id="dropdownMenuNav" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              <i className="fas fa-chevron-circle-down"></i>
            </button>
            <div className="dropdown-menu" aria-labelledby="dropdownMenuNav">
              {switchButtonSmall}
              <a className="dropdown-item" href="#" onClick={(e) => this.editMod(e, mod)} alt={i18next.t("admin.edit")}>
                <i className="fas fa-edit btn-icon"></i>
                {i18next.t("admin.edit")}
              </a>
              <a className="dropdown-item" href="#" onClick={(e) => this.deleteMod(e, mod)} alt={i18next.t("admin.delete")}>
                <i className="fas fa-trash btn-icon"></i>
                {i18next.t("admin.delete")}
              </a>
              {buttonUpSmall}
            </div>
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
            <button disabled={!this.state.loggedIn} type="button" className="btn btn-secondary" onClick={(e) => this.addMod(e)} title={i18next.t("admin.add")}>
              <i className="fas fa-plus"></i>
            </button>
          </th>
        </tr>
        <tr>
          <th className="d-none d-lg-table-cell">
            {i18next.t("admin.order")}
          </th>
          <th>
            {i18next.t("admin.type")}
          </th>
          <th>
            {i18next.t("admin.name")}
          </th>
          <th className="d-none d-lg-table-cell">
            {i18next.t("admin.display-name")}
          </th>
          <th className="d-none d-lg-table-cell">
            {i18next.t("admin.readonly")}
          </th>
          <th className="d-none d-lg-table-cell">
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
