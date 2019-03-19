import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class UserMod extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      mods: props.mods,
      curMod: {},
      add: false
    }

    this.addMod = this.addMod.bind(this);
    this.editMod = this.editMod.bind(this);
    this.deleteMod = this.deleteMod.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      mods: nextProps.mods
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

	render() {
    var mods = [];
    this.state.mods.forEach((mod, index) => {
      mods.push(<tr key={index}>
        <td>{mod.order_rank}</td>
        <td>{mod.name}</td>
        <td>{mod.display_name||""}</td>
        <td>{(mod.readonly?i18next.t("admin.yes"):i18next.t("admin.no"))}</td>
        <td>
          <div className="btn-group" role="group">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.editScope(e, mod)} title={i18next.t("admin.edit")}>
              <i className="fas fa-edit"></i>
            </button>
            <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteScope(e, mod)} title={i18next.t("admin.delete")}>
              <i className="fas fa-trash"></i>
            </button>
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
        </tr>
        <tr>
          <th>
            {i18next.t("admin.order")}
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
