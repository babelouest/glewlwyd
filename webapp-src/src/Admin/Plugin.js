import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class Plugin extends Component {
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
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      mods: nextProps.mods,
      types: nextProps.types
    });
  }

  addMod(e) {
    messageDispatcher.sendMessage('App', {type: "add", role: "plugin"});
  }

  editMod(e, mod) {
    messageDispatcher.sendMessage('App', {type: "edit", role: "plugin", mod: mod});
  }

  deleteMod(e, mod) {
    messageDispatcher.sendMessage('App', {type: "delete", role: "plugin", mod: mod});
  }

	render() {
    var mods = [];
    this.state.mods.forEach((mod, index) => {
      var module = "";
      this.state.types.forEach((type) => {
        if (mod.module === type.name) {
          module = type.display_name;
        }
      });
      mods.push(<tr key={index}>
        <td>{module}</td>
        <td>{mod.name}</td>
        <td>{mod.display_name||""}</td>
        <td>{(mod.enabled?i18next.t("admin.yes"):i18next.t("admin.no"))}</td>
        <td>
          <div className="btn-group" role="group">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.editMod(e, mod)} title={i18next.t("admin.edit")}>
              <i className="fas fa-edit"></i>
            </button>
            <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteMod(e, mod)} title={i18next.t("admin.delete")}>
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
          <th colSpan="3">
            <h4>{i18next.t("admin.plugin-mod-list-title")}</h4>
          </th>
          <th colSpan="1">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.addMod(e)} title={i18next.t("admin.add")}>
              <i className="fas fa-plus"></i>
            </button>
          </th>
        </tr>
        <tr>
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

export default Plugin;
